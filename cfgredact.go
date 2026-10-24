// Package cfgredact hides secrets in config values before they leave a
// trust boundary. A value can be JSON, JSONC, YAML, or INI and env lines.
// Secrets are found by key name, at any depth, and in strings nested inside
// other config values.
//
//	r := cfgredact.Redactor{Secret: regexp.MustCompile(`(?i)password`)}
//	r.String(`{"user": "a", "password": "x"}`) // {"password":"[redacted]","user":"a"}
//
// A value with nothing to hide comes back byte for byte. A redacted value
// is re-encoded in its own format, so comments and key order are lost.
// A value that names a secret but that no parser accepts becomes the
// marker.
package cfgredact

import (
	"fmt"
	"regexp"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// DefaultMarker replaces a hidden value.
const DefaultMarker = "[redacted]"

// DefaultPattern matches secret names. It is the rule when
// Redactor.Secret is nil.
const DefaultPattern = `(?i)(passw|psk|secret|token|credential|private.?key|api.?key|access.?key|auth.?key|setup.?key)`

var defaultSecret = regexp.MustCompile(DefaultPattern)

// Redactor hides secrets. The zero value uses the defaults. A Redactor is
// safe for concurrent use.
type Redactor struct {
	// Secret matches secret names. Nil means DefaultPattern. It also runs
	// on raw text: on comments, on lines and on values that no parser
	// accepts. So it must match a secret name anywhere in a text. Do not
	// anchor it with ^ or $.
	Secret *regexp.Regexp
	// Marker replaces a hidden value. Empty means DefaultMarker.
	Marker string
	// SkipPEM keeps PEM private-key blocks.
	SkipPEM bool
	// SkipURLPassword keeps the password in scheme://user:pass@host.
	SkipURLPassword bool
}

// maxNest is how deep strings may nest inside strings. A deeper string
// becomes the marker. Each level parses the text again, so the cap keeps
// nested YAML block scalars and "a=a=a=..." lines linear.
const maxNest = 16

// String hides the secrets in one config value.
func (r Redactor) String(s string) string { return r.call().str(s, 0) }

// Tree hides the secrets in a parsed value: map[string]any,
// map[string]string, map[any]any, []any, []string and scalars. Strings
// are handled as config values. Other types come back unchanged. Tree does
// not change v.
func (r Redactor) Tree(v any) any {
	out, _ := r.call().walk(v, 0)
	return out
}

// call is one String or Tree call. It remembers the result for each
// string and depth. YAML aliases repeat a string many times, and a text
// can be read twice at one level, so without memo the work could grow
// with each copy.
type call struct {
	Redactor
	memo map[memoKey]string
}

type memoKey struct {
	s     string
	depth int
}

func (r Redactor) call() *call {
	return &call{Redactor: r, memo: map[memoKey]string{}}
}

// str runs the value rules, then parse. Text that no parser accepts
// becomes the marker if it names a secret, or if a YAML reading of it
// hides something. The line pass runs last on every output, as it does in
// rehearse.
//
// There is no early return for text that does not match the secret rule.
// An escaped key such as {"\u0070sk": "x"} names a secret only after
// parsing.
func (r *call) str(s string, depth int) string {
	k := memoKey{s, depth}
	if out, ok := r.memo[k]; ok {
		return out
	}
	out := r.str1(s, depth)
	r.memo[k] = out
	return out
}

func (r *call) str1(s string, depth int) string {
	if depth > maxNest {
		return r.marker()
	}
	if plainRE.MatchString(s) {
		return s
	}
	s = r.values(s)
	// YAML 1.1 breaks lines at U+0085, U+2028 and U+2029. rehearse's line
	// rule does not. The readings disagree, so such text fails closed when
	// it names a secret. A quoted YAML value can hold them as escapes, as
	// in "\P".
	if strings.ContainsAny(s, "\u0085\u2028\u2029") && r.secret().MatchString(s) {
		return r.marker()
	}
	if out, ok := r.parse(s, depth); ok {
		return r.linePass(out)
	}
	out, ok := s, true
	if r.secret().MatchString(s) {
		out, ok = r.keyLines(s)
	}
	if !ok || r.yamlHides(s, depth) {
		return r.marker()
	}
	return out
}

// parse tries JSON, JSONC, YAML maps and lists, Lines, then YAML scalars.
// The first parser that accepts s wins. YAML maps and lists come before
// Lines, as in rehearse: "0=!psk: x" is a map with the key "0=!psk". It
// returns ok=false when no parser accepts s.
func (r *call) parse(s string, depth int) (string, bool) {
	if out, ok := r.fromJSON(s, depth); ok {
		return out, true
	}
	if out, ok := r.fromJSONC(s, depth); ok {
		return out, true
	}
	doc, isYAML := yamlDoc(s)
	if isYAML && len(doc.Content) > 0 && doc.Content[0].Kind != yaml3.ScalarNode {
		return r.fromYAML(s, depth)
	}
	// rehearse read text through sigs.k8s.io/yaml, which accepts some
	// text that yaml.v3 rejects. If that reading hides something, Lines
	// would keep a value that rehearse hid.
	if _, hides := r.sigsHides(s, depth); hides {
		return r.marker(), true
	}
	if out, ok := r.fromLines(s, depth); ok {
		return out, true
	}
	if isYAML {
		return r.fromScalar(s, doc, depth), true
	}
	return "", false
}

// plainRE matches text that every path returns unchanged. No parser
// sees structure or a comment in it, and the value rules and line pass
// need ":", "=" or "-". It must not start with ".", because "..." ends a
// YAML document. Most leaf strings match, so this keeps large lists fast.
var plainRE = regexp.MustCompile(`^([\w +][\w .+]*)?$`)

// walk returns a copy of v and whether anything was hidden.
func (r *call) walk(v any, depth int) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out, changed := make(map[string]any, len(t)), false
		named := r.named(t["name"]) || r.named(t["key"])
		for k, e := range t {
			out[k], changed = r.member(k, e, named, depth, changed)
		}
		return out, changed
	case map[any]any:
		out, changed := make(map[any]any, len(t)), false
		named := r.named(t["name"]) || r.named(t["key"])
		for k, e := range t {
			out[k], changed = r.member(fmt.Sprint(k), e, named, depth, changed)
		}
		return out, changed
	case map[string]string:
		out, changed := make(map[string]string, len(t)), false
		named := r.named(t["name"]) || r.named(t["key"])
		for k, e := range t {
			var w any
			w, changed = r.member(k, e, named, depth, changed)
			out[k] = w.(string)
		}
		return out, changed
	case []any:
		out, changed := make([]any, len(t)), false
		for i, e := range t {
			var c bool
			out[i], c = r.walk(e, depth)
			changed = changed || c
		}
		return out, changed
	case []string:
		out, changed := make([]string, len(t)), false
		for i, e := range t {
			out[i] = r.str(e, depth+1)
			changed = changed || out[i] != e
		}
		return out, changed
	case string:
		if s := r.str(t, depth+1); s != t {
			return s, true
		}
	}
	return v, false
}

// named reports whether v is a secret name. A name/value pair, such as an
// env entry or an Argo CD parameter, holds the secret name in "name" or
// "key", not in the map key.
func (r *call) named(v any) bool {
	n, ok := v.(string)
	return ok && r.secret().MatchString(n)
}

// member returns the walked value of map entry k and the updated changed
// flag.
func (r *call) member(k string, e any, named bool, depth int, changed bool) (any, bool) {
	if r.secret().MatchString(k) || (named && k == "value") {
		return r.marker(), true
	}
	w, c := r.walk(e, depth)
	return w, changed || c
}

// Value rules catch secrets under names the secret rule misses.
var (
	pemRE      = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
	userinfoRE = regexp.MustCompile(`(://[^:/@\s]+:)[^@\s/]+@`)
)

func (r *call) values(s string) string {
	if !r.SkipPEM {
		s = pemRE.ReplaceAllLiteralString(s, r.marker())
	}
	if !r.SkipURLPassword {
		// "$$" keeps a "$" in the marker literal.
		s = userinfoRE.ReplaceAllString(s, "${1}"+strings.ReplaceAll(r.marker(), "$", "$$")+"@")
	}
	return s
}

// lineRE matches "key = value", "key: value", "export KEY=value" and quoted
// keys. It is rehearse's rule. It also hides {psk0=x}, which YAML parses as
// a key named "psk0=x".
var lineRE = regexp.MustCompile(`^(\s*(?:export\s+)?"?([\w.-]+)"?\s*[=:]\s*)(.+)$`)

// linePass hides the value of each line with a secret key. A value that is
// already the marker is kept, so YAML keeps it quoted.
func (r *call) linePass(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		m := lineRE.FindStringSubmatch(l)
		if m == nil || !r.secret().MatchString(m[2]) || strings.Trim(m[3], "'\"\r") == r.marker() {
			continue
		}
		lines[i] = m[1] + r.marker()
	}
	return strings.Join(lines, "\n")
}

// keyLines hides secrets in text that no parser accepts, such as a Helm
// template of YAML or INI. Every line must have one of a few plain shapes:
// see keyLineRE and otherLineRE. Any other line fails closed. So syntax
// that can carry a value onto later lines, such as "(", "<<", "\", "|",
// "$" or an open quote, is never kept, in any language.
//
// A line that names a secret must be one of:
//   - a "#" comment, which is hidden whole
//   - a key line with a secret key and a value, which keeps its key and
//     hides the value, if the next line with content is not deeper
//
// A secret name anywhere else fails closed. A value such as
// "name: DB_PASSWORD" may pair with a value on another line. A [section]
// or an action such as {{ define "app.token" }} names the lines after it.
//
// ponytail: names are read from the raw text. A name escaped as "\x70sk"
// or split by a template action is kept, and so is a secret on a line
// that does not name it. rehearse keeps both too.
func (r *call) keyLines(s string) (string, bool) {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		t := strings.TrimLeft(strings.TrimSuffix(l, "\r"), " ")
		m := keyLineRE.FindStringSubmatchIndex(t)
		if m == nil && !otherLineRE.MatchString(t) {
			return "", false
		}
		if !r.secret().MatchString(t) {
			continue
		}
		in := len(l) - len(strings.TrimLeft(l, " "))
		switch {
		case m == nil && t[0] == '#':
			lines[i] = l[:in] + r.marker()
		case m != nil && r.secret().MatchString(t[m[4]:m[5]]) && !continues(l, lines[i+1:]):
			lines[i] = l[:in] + t[:m[3]] + r.marker()
		default:
			return "", false
		}
	}
	return strings.Join(lines, "\n"), true
}

// The shapes keyLines accepts, after the indent. A value is "{{ }}"
// actions, closed quotes and plain characters. Only spaces separate,
// never tabs, so every reader splits the line the same way. No "\" is
// kept outside an action: a .properties reader joins a line that ends in
// one, even after a "#", to the next line.
const (
	actionText  = `\{\{[^}]*\}\}`
	valueText   = `(?:` + actionText + `|"[^"\\]*"|'[^'\\]*'|[\w .,:/@%+=~-])+`
	commentText = `(?: +#[^\\]*)?`
)

var (
	// keyLineRE matches "key: value" and "key = value", after any "- "
	// list marks. Group 1 ends before the value. Group 2 is the key.
	keyLineRE = regexp.MustCompile(`^((?:- +)*([\w.-]+)(?:: +| *= *))` + valueText + commentText + `$`)
	// otherLineRE matches a blank line, a comment, a line of "{{ }}"
	// actions, a [section], "key:" with no value and a "- value" item.
	otherLineRE = regexp.MustCompile(`^(?:|#.*|(?:` + actionText + ` *)+|\[[\w .-]+\]|(?:- +)*[\w.-]+:` + commentText + `|(?:- +)+` + valueText + commentText + `)$`)
)

// continues reports whether a line after l carries its value on. YAML and
// INI go on at a deeper line, and a deeper "#" line may be block scalar
// content. Blank lines, and comment lines no deeper than l, are skipped,
// since INI keeps a value going past them.
func continues(l string, rest []string) bool {
	in := indent(l)
	for _, n := range rest {
		t := strings.TrimLeft(n, " \t")
		switch {
		case strings.TrimSpace(t) == "":
			continue
		case indent(n) > in:
			return true
		case t[0] == '#' || t[0] == ';':
			continue
		}
		return false
	}
	return false
}

func indent(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }

func (r Redactor) secret() *regexp.Regexp {
	if r.Secret == nil {
		return defaultSecret
	}
	return r.Secret
}

func (r Redactor) marker() string {
	if r.Marker == "" {
		return DefaultMarker
	}
	return r.Marker
}
