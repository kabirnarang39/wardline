## Summary

<!-- What does this change do, and why? -->

## Changes

<!-- Bullet the notable changes. -->

## Checklist

- [ ] `go test ./...` passes
- [ ] `golangci-lint run` is clean
- [ ] New behavior has tests (unit tests with fakes for `usecase/`; narrow integration test for `adapter/`)
- [ ] Post-v0.1 capability is gated behind a feature flag (see `CLAUDE.md`)
- [ ] Docs updated under `docs-site/content/` if behavior changed
- [ ] Dependencies point inward only — `domain/`/`usecase/` import no adapter or framework

## Related issues

<!-- Fixes #NNN -->
