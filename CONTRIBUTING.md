# Contributing to Wardline

Wardline is Apache-2.0 licensed and welcomes contributions.

## Before you start

Read [`CLAUDE.md`](CLAUDE.md) in the repo root — it is the canonical
engineering-conventions doc (Clean Architecture, feature-sliced structure,
feature-flag policy, testing conventions). Contributions are expected to
follow it.

Open an issue before a large change — especially anything touching the
composition root (`cmd/wardline/main.go`) or a domain interface other
features depend on.

## Development

```bash
go build ./cmd/wardline   # build the binary
go test ./...             # run the full test suite
golangci-lint run         # lint (config in .golangci.yml)
make demo                 # run the live auto-block demo
```

CI runs build, `go test -race`, and `golangci-lint` on every pull request.
Keep all three green.

## Conventions (summary — see `CLAUDE.md` for the full rules)

- **Feature-sliced Clean Architecture.** A feature owns its full vertical
  under `internal/features/<name>/{domain,usecase,adapter}`. Dependencies
  point inward only; `domain/` and `usecase/` never import an adapter or a
  framework.
- **Tests.** Every `usecase/` package gets unit tests with fakes for its
  domain interfaces; every `adapter/` package gets a narrow integration
  test against the real thing it wraps. Stdlib `testing` + `testify/assert`.
- **Feature flags.** Every capability beyond the v0.1 baseline (proxy +
  policy + audit) ships behind a flag in `internal/platform/flags`.
- **Errors.** Wrap with `fmt.Errorf("...: %w", err)`; never swallow errors
  in policy/audit paths.

## Pull requests

- One logical change per PR.
- Include tests for new behavior.
- Update relevant docs under `docs-site/content/` when behavior changes.
- Ensure `go test ./...` and `golangci-lint run` pass locally.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. See
[`SECURITY.md`](SECURITY.md).
