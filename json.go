package cfgredact

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/tailscale/hujson"
)

// fromJSON re-encodes only when something was hidden, or when a key
// repeats. JSON has no comments, so an unchanged walk means unchanged
// bytes. With a repeated key, the decoder keeps the last value. The
// re-encode drops the others, which may hold a secret.
func (r *call) fromJSON(s string, depth int) (string, bool) {
	v, dup, ok := decodeJSON([]byte(s))
	if !ok {
		return "", false
	}
	if w, changed := r.walk(v, depth); changed || dup {
		return encodeJSON(w), true
	}
	return s, true
}

// fromJSONC accepts JSON with comments and trailing commas. Any secret
// name in the raw text triggers a re-encode, because it may sit in a
// comment that the walk never sees.
func (r *call) fromJSONC(s string, depth int) (string, bool) {
	// hujson has no depth limit. 1 MiB of "[" overflows the stack, which
	// Go cannot recover from. encoding/json stops at 10000 levels.
	// ponytail: counts brackets, not depth. A large JSONC value with more
	// than 10000 brackets falls through to YAML or fails closed.
	if strings.Count(s, "[")+strings.Count(s, "{") > 10000 {
		return "", false
	}
	// hujson needs a newline to end a line comment, even at the end.
	b, err := hujson.Standardize([]byte(s + "\n"))
	if err != nil {
		return "", false
	}
	v, dup, ok := decodeJSON(b)
	if !ok {
		return "", false
	}
	if w, changed := r.walk(v, depth); changed || dup || r.secret().MatchString(s) {
		return encodeJSON(w), true
	}
	return s, true
}

// decodeJSON decodes exactly one JSON value and reports whether a key
// repeats. Numbers stay json.Number, so a re-encode keeps big integers.
func decodeJSON(b []byte) (v any, dup bool, ok bool) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return nil, false, false
	}
	return v, dupKeys(b), true
}

// dupKeys reports whether an object in valid JSON b repeats a key.
func dupKeys(b []byte) bool {
	// Each frame is an open object (keys != nil) or array. wantKey says
	// that the next token in an object is a key.
	type frame struct {
		keys    map[string]bool
		wantKey bool
	}
	var st []*frame
	d := json.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.Token()
		if err != nil {
			return false
		}
		if n := len(st); n > 0 && st[n-1].wantKey {
			if k, ok := t.(string); ok {
				if st[n-1].keys[k] {
					return true
				}
				st[n-1].keys[k], st[n-1].wantKey = true, false
				continue
			}
		}
		switch t {
		case json.Delim('{'):
			st = append(st, &frame{keys: map[string]bool{}, wantKey: true})
			continue
		case json.Delim('['):
			st = append(st, &frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			st = st[:len(st)-1]
		}
		// A value ended. In an object, a key comes next.
		if n := len(st); n > 0 && st[n-1].keys != nil {
			st[n-1].wantKey = true
		}
	}
}

// encodeJSON encodes v compactly, without HTML escapes.
func encodeJSON(v any) string {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(v) // ponytail: v comes from decodeJSON, so Encode cannot fail
	return strings.TrimSuffix(b.String(), "\n")
}
