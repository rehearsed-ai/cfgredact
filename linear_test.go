package cfgredact

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// fast fails if String takes 1 s or more, or leaks SENTINEL. The design
// asks for 1 MiB "well under one second". The text heuristics that
// cfgredact replaced took 65 s, 3 min and 4 s on inputs like these.
func fast(t *testing.T, name, in string) {
	t.Helper()
	start := time.Now()
	out := testRedactor.String(in)
	if d := time.Since(start); d >= time.Second {
		t.Errorf("%s: took %v", name, d)
	}
	if strings.Contains(in, "SENTINEL") && strings.Contains(out, "SENTINEL") {
		t.Errorf("%s: leaks", name)
	}
}

func TestLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("linear-time benchmark-style test")
	}

	pairs := strings.Repeat(`{"name": "DB_PASSWORD", "value": "SENTINEL"}, `, 30000)
	nest := `{"psk":"SENTINEL"}`
	for range 14 {
		nest = encodeJSON(map[string]any{"psk": "SENTINEL", "n": nest})
	}
	var blocks strings.Builder
	for i := range 1000 {
		fmt.Fprintf(&blocks, "%sl%d: |\n", strings.Repeat("  ", i), i)
	}
	blocks.WriteString(strings.Repeat("  ", 1000) + "psk: SENTINEL\n")
	var yamlMap, linesMap strings.Builder
	for i := range 1 << 16 {
		fmt.Fprintf(&yamlMap, "k%d: v\n", i)
		fmt.Fprintf(&linesMap, "k%d = v\n", i)
	}
	var deep strings.Builder
	for i := range 31 {
		fmt.Fprintf(&deep, "%sl%d: |\n", strings.Repeat("  ", i), i)
	}
	deep.WriteString(strings.Repeat("  ", 31) + "a: " + strings.Repeat("x", 1<<20) + "\n")
	var laterMap strings.Builder
	laterMap.WriteString("x: 1\n---\n")
	for i := range 1 << 16 {
		fmt.Fprintf(&laterMap, "k%d: v\n", i)
	}
	firstMap := strings.TrimPrefix(laterMap.String(), "x: 1\n---\n") + "---\nx: 1\n"
	// Distinct leaves miss the memo, so this one checks the plain fast path.
	var distinct strings.Builder
	distinct.WriteString("[")
	for i := range 1 << 19 {
		fmt.Fprintf(&distinct, `"a%d",`, i)
	}
	distinct.WriteString(`"a"]`)
	aliases := "a: &a \"" + strings.Repeat("k = v\\n", 16384) + "\"\nb: [" + strings.Repeat("*a, ", 1000) + "x]\n"
	bomb := "a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n"
	for _, c := range "bcdefghi" {
		p := string(c - 1)
		bomb += fmt.Sprintf("%c: &%c [*%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s]\n", c, c, p, p, p, p, p, p, p, p, p, p)
	}
	bomb += "token: SENTINEL\n"
	for name, in := range map[string]string{
		"quotes":      "token: " + strings.Repeat(`'\'`, 1<<18) + "SENTINEL",
		"yaml spaces": "password: " + strings.Repeat(" ", 1<<20) + "SENTINEL",
		"yaml blocks": blocks.String(),
		// Plain text keeps its bytes, so this one checks time only.
		"comments":           strings.Repeat("/*", 1<<19) + "token",
		"alias bomb":         bomb,
		"entry chain":        strings.Repeat("a=", 1<<19) + "SENTINEL",
		"yaml list":          strings.Repeat("- a\n", 1<<18),
		"string array":       "[" + strings.Repeat(`"a",`, 1<<18) + `"a"]`,
		"distinct strings":   distinct.String(),
		"templated lines":    "a: {{ .A }}\n" + strings.Repeat("  token: \"SENTINEL\"\n\n# c\n", 1<<16),
		"yaml map":           yamlMap.String(),
		"lines":              linesMap.String(),
		"block around 1 MiB": deep.String(),
		"later document map": laterMap.String(),
		"first document map": firstMap,
		"alias copies":       aliases,
		"templated pairs":    `{"b": {{ .B }}, "env": [` + pairs + `{}]}`,
		"json pairs":         `{"env": [` + pairs + `{}]}`,
		"json spaces":        `{"token": "` + strings.Repeat(" ", 1<<20) + `SENTINEL"}`,
		"json in json":       nest,
		"brackets":           strings.Repeat("[", 1<<20),
		"braces":             strings.Repeat("{", 1<<20),
	} {
		fast(t, name, in)
	}
}
