---
title: "gRPC Transport"
weight: 75
summary: "Front a gRPC upstream on a second listener, running the same identity, policy, budget, audit, and auto-block pipeline as the HTTP proxy."
---

Alongside the HTTP/MCP reverse proxy, Wardline can front a gRPC upstream on
a second listener, gated by the `grpc_transport` feature flag. It is a
transparent raw-bytes passthrough proxy — it needs no `.proto` files or
generated stubs for the services it fronts, so any gRPC API works unchanged
behind it.

```yaml
features:
  grpc_transport: true
grpc_listen: ":8081"              # host:port to accept gRPC on (required)
grpc_upstream: "localhost:50051" # upstream gRPC target (required)
```

Both `grpc_listen` and `grpc_upstream` are required when the flag is on;
`validate-config` rejects the config otherwise. `grpc_upstream` is a plain
gRPC target (`host:port`), not a URL.

## The control plane, unchanged

Each gRPC call runs the same `identity → auto-block → policy → budget →
audit` pipeline as the HTTP path, reusing the same policy engine, budget
buckets, and audit trail:

- **Identity** comes from the `x-wardline-identity` (and optional
  `x-wardline-tenant`) gRPC metadata, exactly as the HTTP path reads the
  `X-Wardline-Identity`/`X-Wardline-Tenant` headers. When
  [`credential_issuance`](/features/credential-issuance/) is on, a Bearer
  token in the `authorization` metadata is verified instead.
- **Policy** evaluates under the method namespace `grpc`, with the full
  gRPC method name (e.g. `/pkg.Service/Method`) as the `tool`. A blank
  `method` still means `tools/call`, so no existing MCP rule accidentally
  matches a gRPC call. A rule reads:

  ```yaml
  - identity: agent-abc123
    method: grpc
    tool: /grpc.health.v1.Health/Check
    effect: allow
  ```

- **Budget**, **audit**, and **auto-block** apply identically — the gRPC
  method is the budget/audit key. A denied or auto-blocked call returns a
  `PermissionDenied` gRPC status.

## Out of scope for this cut

- **TLS to the upstream** — the connection to `grpc_upstream` is plaintext
  today; terminate TLS at ingress.
- **Per-message policy evaluation** — one decision is made per RPC at
  stream start, mirroring the HTTP transport's one-decision-per-request.
