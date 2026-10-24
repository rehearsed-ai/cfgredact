# cfgredact design

Date: 2026-10-21. Status: approved 2026-10-21.

## Why

rehearse sends cluster config out of the cluster. `internal/redact.ConfigValue` hides secrets in one config value: a ConfigMap entry, an annotation, an env value, or a string nested in Helm values. On main it leaks in several shapes:

- JSONC, where a secret key is not at the start of a line: `{"psk": "x", // c\n"mtu": 1}`.
- Templated JSON: `{"b": {{ .B }}, "auth": {"token": "x"}}` and `{"b": {{ .B }}, "env": [{"name": "DB_PASSWORD", "value": "x"}]}`.
- Comments that name a secret: `/* password: x */`, `# psk = x`.

An earlier branch patched these with text heuristics: a comment scanner, quoted-key matching and name/value pairing over raw text. Three fresh reviews each found new inputs that leaked where main did not, plus quadratic and exponential slowdowns. That branch was dropped. cfgredact is a separate public library with a design that cannot produce that class of bug.

## What it is

A public Go module, `github.com/rehearsedai/cfgredact`, MIT licence, owned by the `rehearsedai` GitHub account. rehearse imports it through `go.mod`. It is generic: other projects use it with their own rules.

Input: one config value as a string, or an already-parsed tree (`map[string]any`, `[]any`, scalars). Output: the same value with secrets hidden.

## Goals

1. Hide secrets found by key name, in any supported format, at any depth, including strings nested inside other config values (JSON inside a YAML value, and so on).
2. Hide the value of a name/value pair whose name is a secret name: `{"name": "DB_PASSWORD", "value": "x"}`, and the same with `"key"`. Argo CD parameters and Helm `extraEnv` use this shape.
3. Callers supply the secret-name rule. rehearse passes its existing pattern.
4. Never hide less than rehearse main (b2628e9) does today. This is enforced by a permanent test (see "Parity test").
5. A value whose raw text never matches the secret-name rule comes back byte for byte.
6. Linear time in the input size. A 1 MiB value must finish well under one second.

## Non-goals

- Value scanning in the style of gitleaks (entropy, token formats). The user decided redaction stays name-based.
- Keeping comments, indentation or key order when something is redacted (user picked option B, below).
- Text matching inside values that no parser accepts. That approach caused every regression on the dropped branch.
- Kubernetes knowledge. Tracked namespaces, Helm release records, Secret handling, env `valueFrom`, container args and annotation prefixes stay in rehearse.

## Anti-goals (failure even if it works)

- Any input where cfgredact sends a secret that rehearse main hides.
- Hand-written scanners over raw text that guess at comments, quotes or brackets.
- Super-linear time on adversarial input. A ConfigMap must not stall the connector.

## Decisions made with the user

**Output format: option B (user choice).** If nothing is redacted, the bytes come back unchanged. If something is redacted, the value is re-encoded in its own format. JSON and JSONC come back as JSON. YAML comes back as YAML. Comments, indentation and trailing commas are dropped, and keys may be re-sorted. Example: a JSONC flannel config with a `PSK` comes back as `{"Backend":{"PSK":"[redacted]","Type":"wireguard"},"Network":"10.244.0.0/16"}`.

**Unparseable values: fail closed (user choice).** If no parser accepts the value and the secret-name rule matches anywhere in its text, the whole value becomes the redaction marker. (Refined on 2026-10-22: templated text that passes a gate keeps its lines. See "As built".) If the rule matches nowhere, the value comes back unchanged. Example: `{"mtu": __CNI_MTU__, "etcd": {"password": "x"}}` becomes `[redacted]` if no parser accepts it, while `{"mtu": __CNI_MTU__, "type": "calico"}` stays unchanged.

**Comments: re-encode on any mention (user choice).** Parsers skip comments, so a secret in a comment (`{"a":1 /* password: x */}`, `# psk = x\nb: 2`) never reaches the walk. Rule: if a value parses as a container and its raw text matches the secret-name rule anywhere, return the re-encoded version even when the walk changed nothing. Re-encoding drops every comment. So no comment detection is needed, and any YAML library works. A harmless comment such as `# rotate the token` also gets reformatted. That is accepted, since it is option B anyway. Examples: `{"a":1 /* password: x */}` gives `{"a":1}`, and `# psk = x\nb: 2` gives `b: 2`.

**Repo:** `github.com/rehearsedai/cfgredact`, MIT (user choice).

**Publishing: build local, publish on ask (user choice).** The plan builds and tests the module in a local directory. rehearse may use it through a `replace` directive while the module is unpublished. Creating the public GitHub repo, pushing, setting up CI and tagging v0.1.0 are separate steps. Each happens only when the user asks. The rehearse migration PR follows the tag.

## How it works (my calls, open to the builder where marked)

Formats, tried in this order. The first parser that accepts the value wins:

1. JSON (`encoding/json`).
2. JSONC: `github.com/tailscale/hujson` standardizes comments and trailing commas away, then JSON parses it. No hand-written comment scanner.
3. Lines: a strict parser for `key = value`, `export KEY=value`, `[section]` headers, `#` and `;` comments, and blank lines. It accepts the value only if every line fits one of these. Builder decides whether `key: value` lines belong here or are left to YAML. The parity test settles it.
4. YAML (`sigs.k8s.io/yaml` or `go.yaml.in/yaml/v3`; builder's choice).

Outcome by parse result:

- **Container (map or list):** walk it. Hide the value under each secret-named key. Hide `value` in any map whose `name` or `key` is a secret name. Recurse into every string value as its own config value. Re-encode if something changed, or if the raw text matches the secret-name rule (the comment rule above).
- **Scalar (plain text):** this is not config. Apply only the value rules below, then return it. Example: `"uses token auth"` stays unchanged. It must not fail closed. Do not round-trip plain text through YAML, which would turn `yes` into `true`. If the text holds a YAML comment that names a secret (`abc # token: x`), drop the comment. The builder chooses how, without a hand-written scanner over the whole value.
- **No parser accepts it:** fail closed as above.

Value rules always run first, on any input: a PEM private-key block becomes the marker, and the password in `scheme://user:pass@host` becomes the marker. Callers can turn each off.

Rehearse's quirks that the builder must keep, because the parity test will demand them. These come from main's `ConfigValue` and `walk` in `internal/redact/secret.go` at b2628e9:

- The line rule: main's `lineRE` redacts `"key" = value`, `key: value` and `export KEY=value` lines with a secret key, even after a YAML re-encode. Example: YAML flow `{psk0=0SENTINEL0}` parses as a key named `psk0=0SENTINEL0`. Main hides it only because the line rule runs on the YAML output. The builder either keeps a line pass on the re-encoded output or treats a secret name inside a key as fail-closed.

## API shape (builder's call within these constraints)

- One entry point for a string and one for a parsed tree. rehearse's `redact.Structured` (Helm values, Argo and Flux objects, CRD objects) maps to the tree entry point, and `redact.ConfigValue` maps to the string entry point.
- The secret-name rule is a caller-supplied predicate or regexp. Ship a sensible default pattern for outside users. rehearse passes its own `SecretPattern`.
- The redaction marker is configurable. rehearse uses `[redacted]`.
- No global state. An options struct or functional options. Safe for concurrent use.
- Go version: match rehearse (`go 1.27`) or lower.

## Parity test

The dropped branch built a differential fuzz harness. It lives in this repo:

- `legacy_test.go` is main's `ConfigValue`, `walk` and regexps, renamed `legacy*`.
- `parity_test.go` holds `FuzzDiff`. If the input contains `SENTINEL` and legacy's output does not, cfgredact's output must not contain it either. The seeds are the inputs that broke the branch.

In cfgredact this becomes a permanent test file. The legacy copy is test-only and is configured with rehearse's secret pattern. CI runs the seeds on every push. A longer fuzz run (60 s or more) happens before each release.

## Tests the builder must include

- Every leak input listed under "Why", plus the seeds in `parity_test.go`.
- No-secret inputs keep their bytes. Examples: `{"sock": "unix:///run/x.sock", "authMode": "token", "mtu": 1400}`, `script: if [ "token" = "$MODE" ]; then echo; fi`, and `{"Network":"10.244.0.0/16"}`.
- Linear time: 1 MiB of `'` and `\'`; 30,000 templated name/value objects; 1 MiB of spaces inside a value; JSON nested in strings 14 levels deep. Each must finish under 2 s. The dropped branch hit 65 s, 3 minutes and 4 s on these.
- Mutation check: every rule has a test that fails when the rule is removed.

## rehearse migration (separate PR after cfgredact v0.1.0)

- `redact.ConfigValue` and `redact.Structured` call cfgredact. `SecretName`, `SecretPattern`, `Args`, `Env`, and the Kubernetes object rules stay in rehearse.
- `docs/cni-profiles.md` (the "keys inside a released ConfigMap value" line) describes the new behaviour.
- Run `make e2e`, `CNI=flannel deploy/dev/e2e.sh` and `make e2e-addons`.

## Calls made by Claude, not the user (check these)

- The format order JSON, JSONC, Lines, YAML, and a strict Lines parser so that INI and env files don't fail closed.
- Plain-text scalars are not config: they never fail closed.
- PEM and URL-password value rules are built in and can be turned off.
- One string entry point and one tree entry point. rehearse's `Structured` maps to the tree entry point.
- A permanent parity test against main's legacy code, run in CI.

## Left to the builder

Package layout, the option names, how formats are detected internally, and the exact marker in YAML (quoted or bare). The choice of YAML library, as long as it is linear and passes parity.

## As built (2026-10-21)

The build and its reviews changed these points. Each one came from a failing test or a fuzz input.

- **Format order:** JSON, JSONC, YAML maps and lists, Lines, YAML plain text. Lines ran before YAML at first, and `0=!psk: x` leaked. rehearse read it as a YAML map.
- **YAML acceptance:** yaml.v3 must read exactly one document. Both YAML libraries read `[auth]\na = 1` as a list and ignore the rest. Text that sigs.k8s.io/yaml reads but this check rejects still fails closed when that reading hides something (`? !!binary cHNr\n--- "`).
- **Comments come from the parser:** the YAML comment trigger uses the comments yaml.v3 reports, not a raw `#`. So `"see #42"` is no comment.
- **Folded secret lines:** a re-encode folds a multi-line plain, quoted or `>` scalar into one line. A `--psk=x` line inside it would then escape rehearse's line rule. If a value must be re-encoded and such a line exists (found from yaml.v3 node positions), the value becomes the marker. If nothing needs a re-encode, the original text goes out and the line rule hides the line, as in rehearse. An earlier version ran the line rule before parsing. Fuzzing showed that this changed how nested block scalars parse, so it was dropped.
- **Non-secret config is kept (user decision):** rehearse's line rule hid the rest of a line after a secret key, so `"psk": "x", "a": "b"` lost `"b"`. rehearse compares that config, so cfgredact keeps it. The parity test allows such a string only when it is under a non-secret key and both implementations keep it when it stands alone (`sideEffectOnly`).
- **Comment-only re-encode:** YAML is re-encoded through yaml.v3 nodes, so scalars keep their text (`0755` stays `0755`).
- **Repeated keys** force a re-encode with the last value. Returning the input bytes would send an earlier secret unhidden. sigs.k8s.io/yaml also merges keys such as `0` and `000000`; a yaml.v2 entry count finds those.
- **Readings only sigs.k8s.io/yaml accepts** (`" psk=: \n0=x"`): if that reading has a secret key, the value becomes the marker before Lines can take it.
- **Limits:** strings nested more than 16 levels deep become the marker. JSONC with more than 10000 brackets is skipped, because hujson has no depth limit and Go cannot recover from a stack overflow.
- **Tree** also walks `map[string]string`, `map[any]any` and `[]string`.
- **API:** `DefaultPattern` is a const. The `Secret` rule must not be anchored, because it also runs on raw text.
- **Templated text keeps its lines (user decision, 2026-10-22):** Helm values on public charts showed the cost of failing closed. `grafana/mimir-distributed` holds `mimir.config`, a templated YAML string of 218 lines that no parser accepts. It became the marker, while rehearse hid 9 lines and kept 209. Now `keyLines` keeps such text when every line has a plain shape, and the value becomes the marker otherwise. The shapes, after an indent of spaces:
  - a blank line, a `#` comment, a line of `{{ }}` actions, a `[section]`
  - `key: value`, `key = value`, `key:` and `- value`, with a bare `[\w.-]+` key
  - a value made of `{{ }}` actions, closed quotes, and the characters `[\w .,:/@%+=~-]`, with an optional ` # comment`
  - no `\` outside an action, even in a comment: a `.properties` reader joins a line that ends in one to the next line, since `#` starts a comment there only at the line start

  A line that names a secret must be a `#` comment, which is hidden whole, or a key line with a secret key and a value, which keeps its key and hides the value. The next line with content must not be deeper. A secret name anywhere else fails closed: in a value (`name: DB_PASSWORD` may pair with another line), in a `[section]`, or in an action (`{{ define "app.token" }}` names its body).

  The first version listed the syntax that fails the gate instead: open quotes, brackets and so on. A second fresh leak hunt then found more than 30 leaks in six classes: `(`, `$(`, `define` and XML openers; heredocs in a value; escaped quotes; pipes into a later line; quoted or other pair names (`'name':`, `ParameterKey`); and Unicode-whitespace indents. Each one was confirmed with the real consumer: Python, bash, Terraform, tomllib, yaml.v3 and configparser. An allow list closes them by construction, and each is a row in `TestTemplated`. Scripts (`.sh`, `.py`, `nginx.conf`, `redis.conf`) stay the marker (user decision). Keeping their lines safely needs a parser for each language.

  Known ceilings:
  - Names are read from the raw text. A name split by a template action (`pass{{""}}word`) is kept when the text holds no other literal secret name. rehearse keeps it too.
  - Multi-line text that YAML reads as one plain scalar keeps its bytes, and only rehearse's line rule runs on it. So a Python or `.netrc` value that happens to be valid YAML keeps a secret on a line that does not name it, as in rehearse.
  - The tree walk pairs only `name` and `key` with `value`, as rehearse does. `ParameterKey`/`ParameterValue` and `option_name`/`value` are not paired.
- **Escaped Unicode line breaks:** text with U+0085, U+2028 or U+2029 that names a secret becomes the marker. A quoted YAML value can hold them as escapes (`\P`). YAML 1.1 breaks lines there and rehearse's line rule does not.
