package cfgredact

import (
	"regexp"
	"strings"
)

// Lines is INI, env and TOML-like text. Every line must be blank, a
// comment, a [section] header or a key = value entry. "key: value" lines
// are left to YAML. The section charset is strict, so YAML such as
// [{psk: x}] is not taken for a header.
var (
	commentRE = regexp.MustCompile(`^\s*[#;]`)
	sectionRE = regexp.MustCompile(`^\s*(\[[\w .-]+\]\s*)?$`)
	entryRE   = regexp.MustCompile(`^(\s*(?:export\s+)?([\w.-]+)\s*=\s*)(.*)$`)
)

// fromLines hides the value of each entry with a secret key. Other values
// go back through String. When something is hidden, or a comment names a
// secret, every comment line is dropped.
func (r *call) fromLines(s string, depth int) (string, bool) {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	changed, comment := false, false
	for _, l := range lines {
		body := strings.TrimSuffix(l, "\r")
		cr := l[len(body):]
		if commentRE.MatchString(body) {
			comment = comment || r.secret().MatchString(body)
			continue
		}
		if sectionRE.MatchString(body) {
			out = append(out, l)
			continue
		}
		m := entryRE.FindStringSubmatch(body)
		if m == nil {
			return "", false
		}
		v := r.marker()
		if !r.secret().MatchString(m[2]) {
			v = r.str(m[3], depth+1)
		}
		changed = changed || v != m[3]
		out = append(out, m[1]+v+cr)
	}
	if !changed && !comment {
		return s, true
	}
	return strings.Join(out, "\n"), true
}
