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
grpc_upstream_tls: false         # dial the upstream over TLS (default plaintext)
```

Both `grpc_listen` and `grpc_upstream` are required when the flag is on;
`validate-config` rejects the config otherwise. `grpc_upstream` is a plain
gRPC target (`host:port`), not a URL.

Set `grpc_upstream_tls: true` to dial the upstream over TLS, verified
against the host's system root pool with the server name taken from
`grpc_upstream`. For an upstream presenting a private-CA certificate, add
that CA to the container's trust store (e.g. a mounted CA bundle) rather
than disabling verification. The default (`false`) keeps the plaintext
dial, which is correct when a mesh/sidecar terminates TLS to the upstream.

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

## Mutual TLS to the upstream via SPIFFE

`grpc_upstream_tls` on its own verifies against the system root pool
only and dials with no client certificate — fine for a plaintext-mesh
sidecar upstream, not enough for an upstream that itself requires
mTLS. Turning on `features.spiffe_workload_identity` (see
[mTLS/SPIFFE Bootstrap](/features/mtls-bootstrap/#wardline-as-a-spiffe-workload-outbound))
makes Wardline fetch its own auto-rotating X.509-SVID from a local
SPIRE agent and present it as the client certificate on this exact
dial — no separate certificate file or manual rotation to manage:

```yaml
features:
  grpc_transport: true
  spiffe_workload_identity: true
grpc_upstream_tls: true
credential:
  spiffe_workload:
    upstream_peer_id: "spiffe://example.org/ns/prod/sa/upstream-service"
```

A private (non-system-root) CA for the upstream's own server
certificate, independent of client-cert presentation, is still trusted
by adding it to the container's trust store rather than through this
flag.

## Out of scope for this cut

- **Per-message policy evaluation** — one decision is made per RPC at
  stream start, mirroring the HTTP transport's one-decision-per-request.
