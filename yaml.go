package cfgredact

import (
	"encoding/base64"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"

	yaml2 "go.yaml.in/yaml/v2"
	yaml3 "go.yaml.in/yaml/v3"
	"sigs.k8s.io/yaml"
)

// fromYAML handles a YAML map or list. It returns s unless something is
// hidden, a key repeats or a comment names a secret. Then it re-encodes,
// which drops every comment. sigs.k8s.io/yaml decodes and encodes, as
// rehearse does. A comment-only re-encode goes through yaml.v3, which
// keeps each scalar as written, so 0755 stays 0755.
//
// With a repeated key the parser keeps the last value, so the re-encode
// drops the others, which may hold a secret.
func (r *call) fromYAML(s string, depth int) (string, bool) {
	doc, v, dup, ok := yamlTree(s)
	if !ok {
		return "", false
	}
	w, changed := r.walk(v, depth)
	comment := r.hiddenComment(s, doc)
	switch {
	case !changed && !dup && !comment:
		return s, true
	case r.folds(s, doc):
		return r.marker(), true
	case !changed && !dup:
		return encodeYAML(doc), true
	}
	b, err := yaml.Marshal(w)
	if err != nil {
		return r.marker(), true
	}
	return string(b), true
}

// folds reports whether a line that rehearse's line rule hides sits inside
// a scalar that YAML folds into one line: a plain, quoted or ">" scalar
// over several lines. A re-encode would put that line after other text,
// where the line pass misses it, as in "cmd: run\n  --psk=x". Such a line
// lies after the start of the scalar and before the next node. A "|"
// scalar keeps its lines, so the nested walk sees them.
func (r *call) folds(s string, doc *yaml3.Node) bool {
	nodes := sortedNodes(doc)
	var lines []string
	for i, n := range nodes {
		if n.Kind != yaml3.ScalarNode || n.Style&yaml3.LiteralStyle != 0 {
			continue
		}
		next := math.MaxInt
		if i+1 < len(nodes) {
			next = nodes[i+1].Line
		}
		if lines == nil {
			lines = yamlBreakRE.Split(s, -1)
		}
		// Node lines count from 1, so lines[n.Line] is the line after it.
		// In a flow collection the scalar can end on the line of the next
		// node, as in "b: x\n psk=y, c: d}". Then that line holds text
		// before the next node, not only indentation and indicators.
		end := next - 1
		if i+1 < len(nodes) && end < len(lines) {
			pre := []rune(lines[end])
			if c := nodes[i+1].Column - 1; c <= len(pre) && strings.TrimLeft(string(pre[:c]), " \t-?:") != "" {
				end = next
			}
		}
		if end <= n.Line {
			continue
		}
		for _, l := range lines[min(n.Line, len(lines)):min(end, len(lines))] {
			if m := lineRE.FindStringSubmatch(l); m != nil && r.secret().MatchString(m[2]) {
				return true
			}
		}
	}
	return false
}

// yamlBreakRE matches a YAML line break. A bare "\r" counts, so node
// line numbers match these lines.
var yamlBreakRE = regexp.MustCompile("\r\n|\r|\n")

// sortedNodes returns every node under doc, sorted by position.
func sortedNodes(doc *yaml3.Node) []*yaml3.Node {
	var nodes []*yaml3.Node
	var add func(n *yaml3.Node)
	add = func(n *yaml3.Node) {
		nodes = append(nodes, n)
		for _, c := range n.Content {
			add(c)
		}
	}
	add(doc)
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		return a.Line < b.Line || a.Line == b.Line && a.Column < b.Column
	})
	return nodes
}

// hiddenComment reports whether a comment in s may name a secret.
// yaml.v3 does not attach every comment to a node, for example one after
// "..." or inside "[ ]". So it also counts the secret names in s against
// those in node values, tags, anchors and attached comments. A surplus
// sits in a comment that no node holds.
func (r *call) hiddenComment(s string, doc *yaml3.Node) bool {
	if !strings.Contains(s, "#") {
		return false
	}
	c := comments(doc)
	if r.secret().MatchString(c) {
		return true
	}
	held := 0
	for _, n := range sortedNodes(doc) {
		held += r.count(n.Value) + r.count(n.Tag) + r.count(n.Anchor)
	}
	return r.count(s) > held
}

func (r *call) count(s string) int { return len(r.secret().FindAllStringIndex(s, -1)) }

// comments joins every comment in the tree under n.
func comments(n *yaml3.Node) string {
	c := []string{n.HeadComment, n.LineComment, n.FootComment}
	for _, e := range n.Content {
		c = append(c, comments(e))
	}
	return strings.Join(c, "\n")
}

// fromScalar handles plain text. Plain text is not config. It keeps its
// bytes unless a comment names a secret. Multi-line text then becomes the
// marker, because the folded value would hide "password = x" lines from
// the line pass. A quoted value is a string, like a nested one, so it is
// config.
func (r *call) fromScalar(s string, doc *yaml3.Node, depth int) string {
	if len(doc.Content) == 0 {
		return s
	}
	n := doc.Content[0]
	if n.Style&(yaml3.DoubleQuotedStyle|yaml3.SingleQuotedStyle) != 0 {
		if v := r.str(n.Value, depth+1); v != n.Value {
			if r.folds(s, doc) {
				return r.marker()
			}
			n.Value = v
			return encodeYAML(doc)
		}
	}
	switch {
	case !r.hiddenComment(s, doc):
		return s
	case strings.Contains(s, "\n"):
		return r.marker()
	}
	return n.Value
}

// yamlHides reports whether a YAML reading of s holds a secret, for text
// that no parser accepted. sigs.k8s.io/yaml reads the first document and
// ignores what follows, and rehearse walks what it reads. yaml.v3 reads
// every document, and its nodes are walked where sigs did not read them.
// An escaped key such as "\x70sk" gets past the raw-text check, but not
// past the walk.
func (r *call) yamlHides(s string, depth int) bool {
	read, hides := r.sigsHides(s, depth)
	if hides || read && yaml.UnmarshalStrict([]byte(s), new(any)) != nil {
		return true
	}
	d := yaml3.NewDecoder(strings.NewReader(s))
	for i := 0; ; i++ {
		var doc yaml3.Node
		if d.Decode(&doc) != nil {
			return false
		}
		if (i > 0 || !read) && r.nodeHides(&doc, depth) {
			return true
		}
	}
}

// sigsHides reports whether s is a map or list to sigs.k8s.io/yaml and
// whether its walk hides something. rehearse read text that way, so a
// secret there must stay hidden, even where yaml.v3 or Lines read the
// text differently, as in " psk=: \n0=x".
func (r *call) sigsHides(s string, depth int) (read, hides bool) {
	var v any
	if yaml.Unmarshal([]byte(s), &v) != nil || !container(v) {
		return false, false
	}
	_, changed := r.walk(v, depth)
	return true, changed
}

// nodeHides reports whether the yaml.v3 tree under n holds a secret key, a
// secret name/value pair or a string that String changes. It reads nodes,
// because the yaml.v3 decoder checks duplicate keys in O(n^2). Aliases are
// skipped: their anchor is read where it is defined.
func (r *call) nodeHides(n *yaml3.Node, depth int) bool {
	switch n.Kind {
	case yaml3.DocumentNode, yaml3.SequenceNode:
		for _, c := range n.Content {
			if r.nodeHides(c, depth) {
				return true
			}
		}
	case yaml3.MappingNode:
		named, value := false, false
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if r.secret().MatchString(keyText(k)) {
				return true
			}
			named = named || (k.Value == "name" || k.Value == "key") && r.secret().MatchString(v.Value)
			value = value || k.Value == "value"
			if k.Kind != yaml3.ScalarNode && r.nodeHides(k, depth) || r.nodeHides(v, depth) {
				return true
			}
		}
		return named && value
	case yaml3.ScalarNode:
		return r.str(n.Value, depth+1) != n.Value
	}
	return false
}

// keyText returns the text of key node k. A !!binary key is decoded, as
// sigs.k8s.io/yaml does.
func keyText(k *yaml3.Node) string {
	if k.Tag == "!!binary" {
		if b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(k.Value), "")); err == nil {
			return string(b)
		}
	}
	return k.Value
}

// yamlTree parses one YAML map or list. It returns the yaml.v3 node, the
// sigs.k8s.io/yaml value and whether two keys became one.
func yamlTree(s string) (doc *yaml3.Node, v any, dup bool, ok bool) {
	doc, ok = yamlDoc(s)
	if !ok {
		return nil, nil, false, false
	}
	if yaml.UnmarshalStrict([]byte(s), &v) != nil {
		dup = true
		if yaml.Unmarshal([]byte(s), &v) != nil {
			return nil, nil, false, false
		}
	}
	// sigs.k8s.io/yaml turns keys into strings, so "0" and 000000 become
	// one key, and strict mode does not see it. yaml.v2, which sigs uses,
	// keeps them apart. yaml.v3 does too, but its duplicate check is
	// O(n^2).
	var v2 any
	if yaml2.Unmarshal([]byte(s), &v2) != nil || entries(v2) != entries(v) {
		dup = true
	}
	return doc, v, dup, container(v)
}

// entries counts the map entries in v at any depth.
func entries(v any) int {
	n := 0
	switch t := v.(type) {
	case map[string]any:
		for _, e := range t {
			n += 1 + entries(e)
		}
	case map[any]any:
		for _, e := range t {
			n += 1 + entries(e)
		}
	case []any:
		for _, e := range t {
			n += entries(e)
		}
	}
	return n
}

// yamlDoc parses exactly one YAML document. It rejects a stream of
// several documents and text after the first node.
func yamlDoc(s string) (*yaml3.Node, bool) {
	var doc yaml3.Node
	d := yaml3.NewDecoder(strings.NewReader(s))
	if d.Decode(&doc) != nil || d.Decode(new(yaml3.Node)) != io.EOF {
		return nil, false
	}
	return &doc, true
}

// encodeYAML encodes doc without comments.
func encodeYAML(doc *yaml3.Node) string {
	dropComments(doc)
	var b strings.Builder
	e := yaml3.NewEncoder(&b)
	e.SetIndent(2)
	_ = e.Encode(doc) // ponytail: doc comes from yamlDoc, so Encode cannot fail
	return b.String()
}

func dropComments(n *yaml3.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		dropComments(c)
	}
}

func container(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}
