# Contributing

Thanks for improving cfgredact.

## Before opening a pull request

1. Open an issue for behavior changes or significant API changes. Explain the input, expected redaction result, and security impact.
2. Keep changes small and add a regression test for every behavior change.
3. Run:

   ```sh
   gofmt -w $(git ls-files '*.go')
   go vet ./...
   go test -race ./...
   ```

4. Do not include real credentials, customer data, or private configuration in issues, commits, tests, or examples.

## Scope

This library redacts values based on caller-supplied secret-name rules. Changes that broaden supported formats or alter redaction behavior need tests for both safe redaction and preservation of non-secret values.

## Reporting a security issue

Do not open a public issue for a suspected leak or bypass. Follow [SECURITY.md](SECURITY.md).
