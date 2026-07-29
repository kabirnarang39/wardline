---
title: "Writing a Policy Backend"
weight: 10
---

Adding a new policy backend never requires changing the usecase that
consumes it (Open/Closed) — a backend is a domain-defined
`policy.Engine` interface implementation:

```go
type Engine interface {
    Evaluate(pc Context) Decision
}
```

`Context` carries the identity, tool name, call parameters, timestamp,
remote address, and user agent for a single request; `Decision`
carries the resulting effect (allow/deny) and reason.

Implement this interface in a new `internal/features/policy/adapter/`
file, wire it as a new `policy_backend` value in
`cmd/wardline/main.go`'s backend-selection switch, and add a
`policy.<yourbackend>.example` file demonstrating the syntax. The
existing `yaml`, `opa`, and `cedar` adapters are the reference
implementations to follow — same interface, same test shape (a fake
policy file, exercised end to end, no mocking the interface itself
since these are the real integration tests for each backend).
