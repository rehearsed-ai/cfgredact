# cfgredact

[![CI](https://github.com/rehearsedai/cfgredact/actions/workflows/ci.yml/badge.svg)](https://github.com/rehearsedai/cfgredact/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rehearsedai/cfgredact.svg)](https://pkg.go.dev/github.com/rehearsedai/cfgredact)
[![License](https://img.shields.io/github/license/rehearsedai/cfgredact)](LICENSE)

Hide secrets in config values before they leave a trust boundary.

```go
import "github.com/rehearsedai/cfgredact"

var r cfgredact.Redactor // defaults: DefaultPattern, "[redacted]"

r.String(`{"user": "a", "password": "x"}`)
// {"password":"[redacted]","user":"a"}

r.String("[auth]\nuser = a\npsk = x\n")
// [auth]
// user = a
// psk = [redacted]
```

## What it does

- Accepts one config value as a string (`String`) or a parsed tree (`Tree`). `Tree` walks `map[string]any`, `map[string]string`, `map[any]any`, `[]any` and `[]string`. Other types come back unchanged.
- Tries JSON, then JSONC, then YAML maps and lists, then INI/env lines, then YAML plain text. The first parser that accepts the value wins. INI-like text that YAML reads as a map, such as `a=!psk: x`, is YAML.
- Hides the value under each key whose name matches the secret rule, at any depth.
- Hides `value` in a map whose `name` or `key` is a secret name, as in env entries and Argo CD parameters.
- Treats every nested string as a config value of its own (JSON inside YAML, and so on).
- Hides PEM private-key blocks and the password in `scheme://user:pass@host`. Set `SkipPEM` or `SkipURLPassword` to keep them.

## Output

- If nothing is hidden, the value comes back byte for byte.
- If something is hidden, the value is re-encoded in its own format: JSONC becomes JSON, and YAML stays YAML. Comments, indentation and key order are lost.
- A comment that names a secret also triggers a re-encode, which drops the comment.
- If a YAML re-encode would fold a secret line, such as `--psk=x` inside a multi-line `>` or plain scalar, into the line above, the value becomes the marker.
- A value that no parser accepts, such as a Helm template, keeps its lines when every line is a plain `key: value`, `key = value`, `- item`, `[section]`, `{{ }}` or `#` comment line. A secret key's value becomes the marker, and a comment that names a secret is hidden. Anything else, such as a script, becomes the marker. So does a stream of several YAML documents that holds a secret.
- An object with a repeated key is re-encoded with the last value, as the parsers read it. The other values are dropped, because one may hold a secret.
- Plain text, such as `uses token auth`, keeps its bytes. If a YAML comment in it names a secret, the comment is dropped. Multi-line plain text with such a comment becomes the marker.
- A comment-only re-encode of YAML keeps each scalar as written (`0755` stays `0755`).
- Each line `key: value`, `key = value` or `export KEY=value` with a secret key is hidden to the end of the line, as rehearse did. In JSON and JSONC, other keys on that line are kept: only the secret's value is hidden.
- Strings nested more than 16 levels deep become the marker.

## What it does not do

- It does not scan values for secrets by shape (entropy, token formats). A secret under an innocent key name is not hidden.
- It has no Kubernetes knowledge.

## Configuration

```go
r := cfgredact.Redactor{
	Secret: regexp.MustCompile(`(?i)(password|token)`), // nil: DefaultPattern
	Marker: "***",                                     // "": DefaultMarker
}
```

`Secret` also runs on raw text: comments, lines and values that no parser accepts. It must match a secret name anywhere in a text, so do not anchor it with `^` or `$`.

A `Redactor` has no mutable state and is safe for concurrent use.

Design notes: [docs/design.md](docs/design.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Do not report suspected secret leaks publicly; use the private process in [SECURITY.md](SECURITY.md).

## License

MIT
