---
title: "Contributing"
weight: 90
---

Wardline is Apache 2.0 licensed and welcomes contributions.

- Read `CLAUDE.md` in the repo root first — it's the canonical
  engineering-conventions doc (Clean Architecture, feature-sliced
  structure, feature-flag policy, testing conventions).
- Every `usecase/` package needs unit tests with fakes for its domain
  interfaces; every `adapter/` package needs a narrow integration test
  against the real thing it wraps.
- `golangci-lint run` must be clean before a PR.
- Open an issue before a large change — especially anything touching
  the composition root (`cmd/wardline/main.go`) or a domain interface
  other features depend on.
