package cfgredact

import (
	"encoding/json"
	"strings"
	"testing"
)

var testRedactor = Redactor{}

var regressionSeeds = []string{
	"include: /etc/conf.d/*.conf\napiKey: |\n  SENTINEL\nenv:\n- name: DB_PASSWORD\n  value: SENTINEL",
	"paths: /var/log/*.log\ncredentials:\n  user: a\n  pass: SENTINEL\nenv:\n- name: DB_PASSWORD\n  value: SENTINEL",
	"a: 'line1\n  # token: q'\nenv:\n- name: DB_PASSWORD\n  value: SENTINEL",
	"{a: 'x\n # y', env: [{name: DB_PASSWORD,\n   value: SENTINEL}]}",
	"{glob: /tmp/*,\n env: [{name: DB_PASSWORD,\n   value: SENTINEL}]}",
	"{\"b\": {{ .B }},\n\"password\": ab]SENTINEL\n}",
	"{\"b\": {{ .B }},\n\"password\": {'u': '}', 'p': 'SENTINEL'}\n}",
	"{\"a\": 1 //b, \"env\": [{\"name\": \"DB_PASSWORD\", \"value\": \"SENTINEL\"}]\n, \"c\": 1}",
	"{url: http://a/b#frag,\n cfg: \"{\\\"psk\\\": \\\"SENTINEL\\\"}\"}",
	"{\"glob\": \"/tmp/*\", \"mode\": \"token\", \"n\": 1,\n \"env\": [{\"name\": \"DB_PASSWORD\", \"value\": \"SENTINEL\"}]}",
	"password: x\nconfig: |\n  psk = SENTINEL\n",
	"{\"conf\":\"[a]\\npsk = SENTINEL\"}",
	"{\n\t\"password\": \"SENTINEL\",\n\t\"b\": {{ .B }}\n}",
	"# token: SENTINEL\r\nb: 2",
	"msg: don't # token: SENTINEL",
	"{\"b\": {{ .B }}, \"env\": [{\"name\": \"DB_PASSWORD\", \"value\": \"SENTINEL\"}]}",
	`{"\u0070sk":"SENTINEL"}`,
	`"\x70sk": SENTINEL`,
	"some text\npassword = SENTINEL",
	"{psk0=0SENTINEL0}",
	"[{psk: SENTINEL}]",
	"k = {psk: SENTINEL}",
	"a = 1\r\npsk = SENTINEL\r\n",
	"a: 1\n---\nenv:\n- name: DB_PASSWORD\n  value: SENTINEL",
	"description: \"ask in #token-rotation\"\nargs: >\n  --listen=:8080\n  --db-password=SENTINEL\n",
	"note: 'hello # token rotation'\ncommand: run\n  --psk=SENTINEL",
	"cfg: '{\"a\": 1 /* token */}'\ncommand: run\n  --psk=SENTINEL",
	"cfg: \"[s]\\n; token rotated\\na = 1\"\ncommand: run\n  --psk=SENTINEL",
	"a: >\n  folded\n  psk=SENTINEL\nb: '# token'",
	"\"\\x70sk\": SENTINEL\n---\n",
	"{\"\\u0070sk\": \"SENTINEL\"}\n{\"a\": 1}",
	"  \"\\x70sk\": SENTINEL\nx",
	"? !!binary cHNr\n: SENTINEL\n---\na: 1",
	`{"a": {"password": "SENTINEL"}, "a": 1}`,
	"{a: {password: SENTINEL}, a: 1}",
}

var sideEffectSeeds = []string{
	"{\n\"psk\": \"x\", \"a\": \"SENTINEL\" /* c */\n}",
	"{\n  \"psk\": \"x\", \"peer\": \"SENTINEL\", // c\n}",
}

func TestSideEffect(t *testing.T) {
	for _, s := range sideEffectSeeds {
		out := (Redactor{}).String(s)
		if strings.Contains(out, `"x"`) || !strings.Contains(out, "SENTINEL") {
			t.Errorf("in: %q\nout: %q", s, out)
		}
	}
}

func TestNoLeak(t *testing.T) {
	why := []string{
		"{\"psk\": \"SENTINEL\", // c\n\"mtu\": 1}",
		`{"b": {{ .B }}, "auth": {"token": "SENTINEL"}}`,
		`{"b": {{ .B }}, "env": [{"name": "DB_PASSWORD", "value": "SENTINEL"}]}`,
		`{"a":1 /* password: SENTINEL */}`,
		"# psk = SENTINEL\nb: 2",
		"a: 1\n---\n\"\\x70sk\": SENTINEL",
		"a: 1\n... # token SENTINEL",
		"%YAML 1.1 # token SENTINEL\n---\na: 1",
		"%TAG !e! tag:example.com,2000: # token SENTINEL\n---\na: 1",
		"args: [ # token SENTINEL\n]",
		"env: { # psk SENTINEL\n}\nb: 1",
		"{0: 0\n# psk SENTINEL\n , }",
		"0:\n # psk SENTINEL\n-",
		"! # psk SENTINEL",
		"0=! # psk SENTINEL",
		"a: 1\n---\nb: '{\"\\u0070sk\": \"SENTINEL\"}'",
		"? [x]\n: y\nb: '{\"\\u0070sk\": \"SENTINEL\"}'",
		"'{\"psk\": \"SENTINEL\"}'",
		`{"a": {"password": "SENTINEL"}, "a": 1}`,
	}
	for _, s := range append(why, regressionSeeds...) {
		if out := (Redactor{}).String(s); strings.Contains(out, "SENTINEL") {
			t.Errorf("leak:\nin:  %q\nout: %q", s, out)
		}
	}
}

func TestSideEffectOnly(t *testing.T) {
	for _, s := range sideEffectSeeds {
		if !sideEffectOnly((Redactor{}).String(s)) {
			t.Errorf("expected a retained non-secret value in %q", s)
		}
	}
}

func sideEffectOnly(out string) bool {
	var v any
	if json.Unmarshal([]byte(out), &v) != nil {
		return false
	}
	var keep func(any) bool
	keep = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			for k, e := range t {
				if strings.Contains(k, "SENTINEL") || !keep(e) {
					return false
				}
			}
		case []any:
			for _, e := range t {
				if !keep(e) {
					return false
				}
			}
		case string:
			if strings.Contains(t, "SENTINEL") {
				return (Redactor{}).String(t) == t
			}
		}
		return true
	}
	return keep(v)
}
