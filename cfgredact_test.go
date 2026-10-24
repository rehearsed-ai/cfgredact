package cfgredact

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const pemValue = `{"k":"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"}`

func TestString(t *testing.T) {
	cases := []struct {
		name string
		r    Redactor
		in   string
		want string
	}{
		{"key", Redactor{}, `{"a":1,"password":"x"}`, `{"a":1,"password":"[redacted]"}`},
		{"name/value", Redactor{}, `{"env":[{"name":"DB_PASSWORD","value":"x"}]}`, `{"env":[{"name":"DB_PASSWORD","value":"[redacted]"}]}`},
		{"key/value", Redactor{}, `{"key":"api_key","value":"x"}`, `{"key":"api_key","value":"[redacted]"}`},
		{"nested string", Redactor{}, `{"cfg":"{\"psk\":\"x\"}"}`, `{"cfg":"{\"psk\":\"[redacted]\"}"}`},
		{"escaped key", Redactor{}, `{"\u0070sk":"x"}`, `{"psk":"[redacted]"}`},
		{"big number", Redactor{}, `{"n":12345678901234567890,"token":"x"}`, `{"n":12345678901234567890,"token":"[redacted]"}`},
		{"no html escape", Redactor{}, `{"u":"a<b","token":"x"}`, `{"token":"[redacted]","u":"a<b"}`},
		{"bytes kept", Redactor{}, `{"sock": "unix:///run/x.sock", "authMode": "token", "mtu": 1400}`, `{"sock": "unix:///run/x.sock", "authMode": "token", "mtu": 1400}`},
		{"bytes kept 2", Redactor{}, `{"Network":"10.244.0.0/16"}`, `{"Network":"10.244.0.0/16"}`},
		{"url password", Redactor{}, `{"url":"postgres://u:pw@db:5432/x"}`, `{"url":"postgres://u:[redacted]@db:5432/x"}`},
		{"SkipURLPassword", Redactor{SkipURLPassword: true}, `{"url":"postgres://u:pw@db:5432/x"}`, `{"url":"postgres://u:pw@db:5432/x"}`},
		{"pem", Redactor{}, pemValue, `{"k":"[redacted]"}`},
		{"marker option", Redactor{Marker: "***"}, `{"token":"x"}`, `{"token":"***"}`},
		{"secret option", Redactor{Secret: regexp.MustCompile("(?i)pin")}, `{"pin":"1","token":"x"}`, `{"pin":"[redacted]","token":"x"}`},
		{"fail closed", Redactor{}, `token: "x`, `[redacted]`},
		{"unparseable, no secret", Redactor{}, `a: "x`, `a: "x`},

		{"jsonc flannel", Redactor{}, "{\n  \"Network\": \"10.244.0.0/16\", // pod CIDR\n  \"Backend\": {\"Type\": \"wireguard\", \"PSK\": \"x\",},\n}", `{"Backend":{"PSK":"[redacted]","Type":"wireguard"},"Network":"10.244.0.0/16"}`},
		{"jsonc comment", Redactor{}, `{"a":1 /* password: x */}`, `{"a":1}`},
		{"jsonc kept", Redactor{}, "{\"a\": 1, // note\n}", "{\"a\": 1, // note\n}"},
		{"jsonc scalar", Redactor{}, `1 // token: x`, `1`},
		{"yaml key", Redactor{}, "a: 1\npassword: x\n", "a: 1\npassword: '[redacted]'\n"},
		{"yaml escaped key", Redactor{}, `"\x70sk": x`, "psk: '[redacted]'\n"},
		{"yaml comment", Redactor{}, "# psk = x\nb: 2", "b: 2\n"},
		{"yaml crlf comment", Redactor{}, "# token: x\r\nb: 2", "b: 2\n"},
		{"yaml kept", Redactor{}, `script: if [ "token" = "$MODE" ]; then echo; fi`, `script: if [ "token" = "$MODE" ]; then echo; fi`},
		{"scalar kept", Redactor{}, "uses token auth", "uses token auth"},
		{"scalar comment", Redactor{}, "abc # token: x", "abc"},
		{"scalar no bool", Redactor{}, "yes # token rotation", "yes"},
		{"scalar multi-line comment", Redactor{}, "hello\nworld # token: x", "[redacted]"},
		{"folded plain text", Redactor{}, "some text\npassword = x", "some text\npassword = [redacted]"},
		{"multi-doc secret", Redactor{}, "a: 1\n---\nenv:\n- name: DB_PASSWORD\n  value: x", "[redacted]"},
		{"multi-doc kept", Redactor{}, "a: 1\n---\nb: 2", "a: 1\n---\nb: 2"},
		{"templated json", Redactor{}, `{"b": {{ .B }}, "auth": {"token": "x"}}`, "[redacted]"},
		{"templated json a yaml reading hides", Redactor{}, "{\n  \"b\": {{ .B }},\n  \"token\": \"x\",\n  \"c\": 1\n}", "[redacted]"},
		{"SkipPEM", Redactor{SkipPEM: true}, pemValue, pemValue},
		{"yaml fold", Redactor{}, "a: b#c\n  psk=x", "a: b#c\n  psk=[redacted]"},

		{"ini", Redactor{}, "[auth]\nuser = a\npsk = x\n", "[auth]\nuser = a\npsk = [redacted]\n"},
		{"single entry", Redactor{}, "password = x", "password = [redacted]"},
		{"env", Redactor{}, "export API_KEY=x\nexport A=b", "export API_KEY=[redacted]\nexport A=b"},
		{"lines comment", Redactor{}, "; token = x\na = 1", "a = 1"},
		{"lines comment kept", Redactor{}, "# note\na = 1", "# note\na = 1"},
		{"lines recurse", Redactor{}, `cfg = {"psk":"x"}`, `cfg = {"psk":"[redacted]"}`},
		{"lines yields to yaml", Redactor{}, "k = {psk: x}", "k = {psk: '[redacted]'\n"},
		{"lines yields to yaml 2", Redactor{}, "0=!psk: x", "0=!psk: '[redacted]'\n"},
		{"lines crlf", Redactor{}, "a = 1\r\npsk = x\r\n", "a = 1\r\npsk = [redacted]\r\n"},
		{"not a header", Redactor{}, "[{psk: x}]", "- psk: '[redacted]'\n"},
		{"not a header 2", Redactor{}, "[{psk: x}]\na = 1", "[redacted]"},

		{"yaml block header", Redactor{}, "password: |\n  x\na: 1", "a: 1\npassword: '[redacted]'\n"},
		{"yaml header and fold", Redactor{}, "password: |\n  x\ncmd: run\n  --psk=x", "[redacted]"},
		{"literal block keeps lines", Redactor{}, "password: a\ncmd: |\n  run\n  --psk=x", "cmd: |-\n  run\n  --psk=[redacted]\npassword: '[redacted]'\n"},
		{"hash in quotes is no comment", Redactor{}, "a: \"see #42\"\nargs: >\n  --listen=:8080\n  --db-password=x\n", "a: \"see #42\"\nargs: >\n  --listen=:8080\n  --db-password=[redacted]\n"},
		{"yaml literal nested", Redactor{}, "0: |\n psk:: \n  x", "\"0\": |\n  'psk:': '[redacted]'\n"},
		{"yaml empty tail", Redactor{}, "0: |\n psk: \n  x", "\"0\": |\n  psk: '[redacted]'\n"},
		{"fold after bare CR", Redactor{}, "0: \"#token\r\"\n0: 0\n psk=x", "[redacted]"},
		{"fold into flow list", Redactor{}, "# the api token comes from a mounted file\ncommand: [/bin/server --listen=:8080\n  --db-password=x, --verbose]", "[redacted]"},
		{"fold into flow map", Redactor{}, "{a: 1, a: 1, b: x\n psk=x, c: d}", "[redacted]"},
		{"fold into nested flow map", Redactor{}, "cfg: |\n  {a: 1, a: 1, b: x\n   psk=x, c: d}", "cfg: '[redacted]'\n"},
		{"fold into flow list, pair", Redactor{}, "command: [/bin/server --listen=:8080\n  --db-password=x, --verbose]\nenv: {name: API_TOKEN, value: abc}\n", "[redacted]"},
		{"sigs gate, nested string", Redactor{}, " k = 'q: '{\"\\u0070sk\": \"x\"}'\n0=x", "[redacted]"},
		{"document end is not plain", Redactor{}, "... token", "[redacted]"},
		{"quoted scalar fold", Redactor{}, "'0\npsk=x #token'", "[redacted]"},
		{"quoted scalar is config", Redactor{}, `'{"psk": "x"}'`, "'{\"psk\":\"[redacted]\"}'\n"},
		{"fallback fold", Redactor{}, "0: 0\n psk=x\n1: ' \npsk='", "[redacted]"},
		{"yaml anchor header", Redactor{}, "token: &t\n  x: 1\na: 1", "a: 1\ntoken: '[redacted]'\n"},
		{"yaml comment keeps scalars", Redactor{}, "mode: 0755 # token\nflag: y", "mode: 0755\nflag: y\n"},
		{"yaml comment keeps quotes", Redactor{}, "a: \"x\" # token\nb: 'y'", "a: \"x\"\nb: 'y'\n"},
		{"yaml fold, walk changed", Redactor{}, "password: a\ncmd: run\n  --psk=x", "[redacted]"},
		{"jsonc tail", Redactor{}, "{\n\"psk\": \"x\", \"a\": \"b\" /* c */\n}", `{"a":"b","psk":"[redacted]"}`},
		{"json duplicate key", Redactor{}, `{"a": {"password": "x"}, "a": 1}`, `{"a":1}`},
		{"json duplicate escaped key", Redactor{}, `{"a": {"\u0070sk": "x"}, "a": 1}`, `{"a":1}`},
		{"yaml duplicate key", Redactor{}, "{a: {password: x}, a: 1}", "a: 1\n"},
		{"yaml line pass breaks parse", Redactor{}, "token: {\n  a: 1}\nb: 2", "b: 2\ntoken: '[redacted]'\n"},
		{"escaped newline after key", Redactor{}, `"pAssw:\n\0x"`, "\"[redacted]\"\n"},
		{"escaped unicode line break", Redactor{}, `"pAssw:\PSENTINELpAssw:"`, "\"[redacted]\"\n"},
		{"later document", Redactor{}, "a: 1\n---\n\"\\x70sk\": x", "[redacted]"},
		{"later document binary key", Redactor{}, "a: 1\n---\n!!binary cHNr: x", "[redacted]"},
		{"later document name/value", Redactor{}, "a: 1\n---\nname: \"\\x70sk\"\nvalue: x", "[redacted]"},
		{"later document complex key", Redactor{}, "a: 1\n---\n? {\"\\x70sk\": x}\n: 1", "[redacted]"},
		{"strict section charset", Redactor{}, "[x] psk = y]\na = b", "[redacted]"},
		{"sigs reading with duplicate", Redactor{}, "{a: {\"\\x70sk\": x}, a: 1}\n{b: 1}", "[redacted]"},
		{"fallback fold with comment", Redactor{}, "a: 'x\n  --psk=q'\nb: 1 # token", "[redacted]"},
		{"sigs map over lines", Redactor{}, " psk=: \n0=x", "[redacted]"},
		{"sigs reading, nested string", Redactor{}, "{\"a\": \"{\\\"\\\\u0070sk\\\": \\\"x\\\"}\"}\n{\"b\": 1}", "[redacted]"},
		{"not a header 3", Redactor{}, "[{a: '{\"psk\":\"x\"}'}]\nb = 1", "[redacted]"},
		{"sigs reading only", Redactor{}, "? !!binary cHNr\n--- \"", "[redacted]"},
	}
	for _, c := range cases {
		if got := c.r.String(c.in); got != c.want {
			t.Errorf("%s:\nin:   %q\ngot:  %q\nwant: %q", c.name, c.in, got, c.want)
		}
	}
}

// TestDepthCap checks that strings nested past maxNest become the marker.
// It nests YAML block scalars, because JSON doubles its escapes per level.
func TestDepthCap(t *testing.T) {
	var b strings.Builder
	for i := range 40 {
		b.WriteString(strings.Repeat("  ", i) + "n: |\n")
	}
	s := b.String() + strings.Repeat("  ", 40) + "a: 1\n"
	if out := (Redactor{}).String(s); !strings.Contains(out, DefaultMarker) {
		t.Errorf("no marker in %q", out)
	}
}

func TestTree(t *testing.T) {
	in := map[string]any{
		"env": []any{map[string]any{"name": "TOKEN", "value": "x"}},
		"cfg": `{"psk":"x"}`,
		"n":   1,
	}
	want := map[string]any{
		"env": []any{map[string]any{"name": "TOKEN", "value": "[redacted]"}},
		"cfg": `{"psk":"[redacted]"}`,
		"n":   1,
	}
	orig := map[string]any{
		"env": []any{map[string]any{"name": "TOKEN", "value": "x"}},
		"cfg": `{"psk":"x"}`,
		"n":   1,
	}
	if got := (Redactor{}).Tree(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v", got)
	}
	if !reflect.DeepEqual(in, orig) {
		t.Errorf("input mutated: %#v", in)
	}
}

// TestTreeTypes checks the other container types a caller may pass, such
// as a ConfigMap's Data.
func TestTreeTypes(t *testing.T) {
	r := Redactor{}
	for _, c := range []struct{ in, want any }{
		{
			map[string]string{"password": "x", "cfg": `{"psk":"x"}`, "a": "b"},
			map[string]string{"password": "[redacted]", "cfg": `{"psk":"[redacted]"}`, "a": "b"},
		},
		{map[string]string{"name": "TOKEN", "value": "x"}, map[string]string{"name": "TOKEN", "value": "[redacted]"}},
		{[]string{`{"psk":"x"}`, "a"}, []string{`{"psk":"[redacted]"}`, "a"}},
		{map[any]any{"token": "x", 1: "b"}, map[any]any{"token": "[redacted]", 1: "b"}},
	} {
		if got := r.Tree(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Tree(%#v) = %#v", c.in, got)
		}
	}
}

// TestKeyCollision checks keys that sigs.k8s.io/yaml maps to one key:
// "0" and 000000 both become "0". Map order picks the value it keeps, so
// the test runs the input many times.
func TestKeyCollision(t *testing.T) {
	in := "{\"0\":10, 000000: [{\"name\": PASSW, \"value\": SENTINEL}]}"
	for range 200 {
		if out := (Redactor{}).String(in); strings.Contains(out, "SENTINEL") {
			t.Fatalf("leak: %q", out)
		}
	}
}

// TestTemplated checks text that no parser accepts, as keyLines sees it.
// Each body sits between "{{- if .X }}" and "{{- end }}", so no YAML
// reading takes it. An empty want means the marker.
func TestTemplated(t *testing.T) {
	const pre, post = "{{- if .X }}\n", "\n{{- end }}"
	cases := []struct{ name, in, want string }{
		// Kept: every line has a plain shape.
		{"keys", "a: 1\npassword: {{ .P }}\ntoken: \"x\"\nb: 2", "a: 1\npassword: [redacted]\ntoken: [redacted]\nb: 2"},
		{"name in secret value", "tokens_path: /data/tokens", "tokens_path: [redacted]"},
		{"quote escape", "password: 'it''s'", "password: [redacted]"},
		{"ini comment", "password = x\n# c\nb = 2", "password = [redacted]\n# c\nb = 2"},
		{"toml one line", "password = '''a'''", "password = [redacted]"},
		{"quotes in action", "password: {{ include \"p\" . }}", "password: [redacted]"},
		{"list key", "- password: x\n- b", "- password: [redacted]\n- b"},
		{"comment names secret", "# password: x", "[redacted]"},
		{"indented comment", "  # set the token\nb: 2", "  [redacted]\nb: 2"},
		{"apostrophe comment", "# don't log the token", "[redacted]"},
		{"ini section", "[db]\npassword = x", "[db]\npassword = [redacted]"},
		{"nested key", "db:\n  password: x", "db:\n  password: [redacted]"},
		{"inline comment", "password: x # note\nb: 2", "password: [redacted]\nb: 2"},
		{"crlf", "a: 1\r\npassword: x\r\nb: 2", "a: 1\r\npassword: [redacted]\nb: 2"},
		// Fail closed: a secret line that could carry its value on.
		{"block scalar", "password: |\n  x", ""},
		{"folded value", "password: x\n  y\nb: 2", ""},
		{"comment then deeper line", "password: x\n# c\n  y\nb: 2", ""},
		{"ini continuation", "[db]\npassword = a\n  b = x", ""},
		{"ini continuation past comment", "[db]\npassword = a\n# c\n  b = x", ""},
		{"empty key", "password:\nx", ""},
		{"empty list key", "- password =\nx", ""},
		{"block hash line", "password: |\n  #x", ""},
		{"same-indent list", "password: # c\n- x", ""},
		{"anchor then list", "password: &a\n- x", ""},
		{"tag then block", "password: !!str\n|\n x", ""},
		// Fail closed: a secret name outside a key.
		{"name in value", "name: DB_PASSWORD\nvalue: x", ""},
		{"pair name list", "- name: DB_PASSWORD\n  value: x", ""},
		{"second key", "b: 1, password: x", ""},
		{"section names secret", "[credentials]\nuser = x", ""},
		{"list item names secret", "- token-x", ""},
		{"action names secret", "{{- define \"app.token\" -}}\nk: x\n{{- end }}", ""},
		// Fail closed: a line outside the grammar.
		{"open quote", "password: \"x\nb: 2", ""},
		{"escaped quote", "password: \"x\\\"\ny\"\nb: 2", ""},
		{"open list", "password: [x,\ny]\nb: 2", ""},
		{"open map", "password: {x,\ny}\nb: 2", ""},
		{"open action", "password: {{ \"x\ny\" }}\nb: 2", ""},
		{"tag opens quote", "password: !!str \"x\ny\"\nb: 2", ""},
		{"list opened before", "b: [\n  password: x\n  y ]", ""},
		{"map opened before", "b: {\n  password: x\n  y }", ""},
		{"quoted closer first", "b: \"]\" [\n  password: x\n  y \"[\" ]", ""},
		{"toml multi-line", "password = '''a'\nx'''", ""},
		{"shell continuation", "export PASSWORD=abc\\\nx", ""},
		{"code key line", "headers = {\"Authorization\": \"Bearer \" + token}", ""},
		{"python env", "TOKEN = os.environ.get(\"X\")\nprint(1)", ""},
		{"call line", "print(get_token())\nx = 1", ""},
		{"nginx block", "server {\n  listen 80;\n}\n# auth token\nlocation / {\n}", ""},
		{"secret inside block", "server {\n  auth_basic_user_file /etc/secrets;\n}", ""},
		{"heredoc", "cat <<EOF > token\nx\nEOF", ""},
		{"open block comment", "/* token\nx */", ""},
		{"odd quote code", "echo \"token\nx\"", ""},
		{"odd backtick value", "x = `token\ny`", ""},
		{"def then body", "def token():\n    return 'x'", ""},
		{"comment continuation", "// token \\\nx", ""},
		// Fail closed: the second leak hunt, one row per class.
		{"python paren", "DB_PASSWORD = (\n\"x\"\n)", ""},
		{"bash array", "PASSWORDS=(\nx\n)", ""},
		{"make define", "define DB_PASSWORD\nx\nendef", ""},
		{"xml element", "<password>\nx\n</password>", ""},
		{"helm define", "{{- define \"app.token\" -}}\nx\n{{- end -}}", ""},
		{"value heredoc", "db_password = <<EOT\nx\nEOT", ""},
		{"escaped quote in plain", "PASSWORD=x\"\\\"\ny\"", ""},
		{"toml escaped triple", "password = \"\"\"\\\"\"\"\nx\"\"\"", ""},
		{"pipe into login", "echo x |\n  docker login --password-stdin", ""},
		{"name on next line", "- name:\n    DB_PASSWORD\n  value: x", ""},
		{"quoted pair name", "- value: x\n  'name': DB_PASSWORD", ""},
		{"cloudformation pair", "- ParameterKey: DbPassword\n  ParameterValue: x", ""},
		{"nbsp indent", "[db]\npassword = a\n\u00a0x", ""},
		{"form feed indent", "[db]\npassword = a\n\fx", ""},
		{"tab indent", "password: a\n\tx", ""},
		{"properties continuation in comment", "password = x # \\\nmore = y", ""},
		{"single quote backslash", "password = 'x\\'\nb = y", ""},
		{"nbsp indented key", "[db]\npassword = a\n\u00a0b = x", ""},
		{"escaped pair name", "password: x\n- name: \"\\x70sk\"\n  value: y", ""},
	}
	for _, c := range cases {
		in, want := pre+c.in+post, "[redacted]"
		if c.want != "" {
			want = pre + c.want + post
		}
		r := testRedactor.call()
		if _, ok := r.parse(in, 0); ok || r.yamlHides(in, 0) {
			t.Errorf("%s: does not reach keyLines", c.name)
		}
		if got := testRedactor.String(in); got != want {
			t.Errorf("%s:\n in:   %q\n got:  %q\n want: %q", c.name, in, got, want)
		}
	}
}
