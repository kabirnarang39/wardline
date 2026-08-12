---
title: "mTLS/SPIFFE Bootstrap"
weight: 26
summary: "Bootstrap credential issuance from an already-verified SPIFFE ID, forwarded by a terminating mTLS proxy or mesh."
---

A third [Credential Issuance](/features/credential-issuance/) bootstrap
adapter, alongside [preshared secrets](/features/credential-issuance/)
and [OIDC](/features/sso/): instead of a secret or an ID token, the
caller's identity comes from an already-verified SPIFFE ID, forwarded by
a terminating mTLS proxy or service mesh (Envoy, Istio, SPIRE's own
agent-side proxy, nginx with `ssl_verify_client`, ...) via a trusted HTTP
header.

**Wardline never terminates TLS or parses an X.509 certificate itself.**
The existing Helm chart decision — an Ingress/LB terminates TLS in front
of Wardline — stands unchanged. This adapter adopts the same pattern
every SPIFFE-aware mesh already uses: the sidecar or gateway completes
the mTLS handshake, verifies the peer certificate against the mesh's
trust bundle, extracts the verified SPIFFE ID (the certificate's URI
SAN), and forwards it to the application — Wardline — as a header.

```yaml
features:
  credential_issuance: true
credential:
  identities_file: "credentials.yaml"
  bootstrap_source: "mtls"
  mtls:
    header: "X-Wardline-Verified-Spiffe-Id"   # required, no default -- name a header your own proxy/mesh actually sets
```

`credential.identities_file` is required whenever `features.credential_issuance`
is on, regardless of `bootstrap_source` — same non-obvious quirk as the
OIDC bootstrap source (see [SSO](/features/sso/)).

`credentials.yaml` maps each allowed SPIFFE ID to an identity and
(optional, defaults to `default`) tenant:

```yaml
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
    tenant: acme
```

An identity bootstraps by presenting the header — no request body is
read at all on this path:

```
POST /credentials/token
X-Wardline-Verified-Spiffe-Id: spiffe://example.org/ns/prod/sa/payments-worker
```

## Trust boundary — read this before enabling

This is a header-based trust handoff, the same class of mechanism as
`X-Forwarded-For` or Envoy's `x-forwarded-client-cert`: safe only if
Wardline is **unreachable except through the proxy/mesh that sets the
header**, and that proxy/mesh **strips or overwrites** any
client-supplied value of the same header before forwarding. Wardline
cannot verify either condition from inside its own process — this is a
deployment requirement your network topology must guarantee, not
something this feature enforces.

`credential.mtls.header` has no default value on purpose: an operator
must explicitly name a header their own ingress/mesh is actually
configured to set, so there's no accidental behavior from a header
nobody intended to trust. A missing or empty header on an actual request
is a generic `401`, the same non-enumerable-failure posture every other
bootstrap source uses.

## Wardline as a SPIFFE workload (outbound)

The known limitation this section used to describe — "no SPIFFE Workload
API client in Wardline itself" — is closed for the outbound direction.
When `features.spiffe_workload_identity` is on, Wardline connects to a
local SPIFFE Workload API (a SPIRE agent's Unix domain socket, the same
one any sidecar in the mesh uses) via
[`go-spiffe/v2`](https://github.com/spiffe/go-spiffe)'s `workloadapi.X509Source`,
fetches its own X.509-SVID, and keeps it rotated automatically for the
lifetime of the process — no restart needed when the SVID nears expiry.
That identity is presented as the client certificate on Wardline's own
outbound [gRPC transport](/features/grpc-transport/) connection to the
upstream, so the upstream can verify *Wardline* the same way every other
workload in a SPIFFE-native mesh verifies its peers:

```yaml
features:
  spiffe_workload_identity: true
  grpc_transport: true
credential:
  spiffe_workload:
    socket_path: "unix:///run/spire/sockets/agent.sock"   # optional, defaults to the SPIFFE_ENDPOINT_SOCKET env var
    upstream_peer_id: "spiffe://example.org/ns/prod/sa/upstream-service"   # optional but strongly recommended, see below
grpc_upstream: "upstream.internal:8443"
grpc_upstream_tls: true
```

`upstream_peer_id` pins the exact SPIFFE ID Wardline requires the
upstream to present; without it, Wardline authorizes any
SPIFFE-authenticated peer, which is weaker and logs a warning on
startup naming the gap. This is unrelated to the inbound bootstrap
header above: `spiffe_workload_identity` governs the identity Wardline
*presents* when calling out; `bootstrap_source: "mtls"` governs how
Wardline *accepts* an already-verified caller identity. Both can be on
at once in a fully SPIFFE-native deployment.

Wardline still never terminates TLS or parses an X.509 certificate for
*inbound* HTTP traffic — that part of "Wardline never terminates TLS"
above is unchanged and remains the documented architecture, not a gap.

## Known limitations

- **No SPIRE agent bundled or managed by Wardline** — Wardline is a
  Workload API *client* only, exactly like every other workload in a
  SPIFFE deployment; running and provisioning the SPIRE agent/server
  (or another SPIFFE-compliant Workload API implementation) is the
  operator's infrastructure, same as this project doesn't bundle
  Postgres or an OIDC provider either.
- This inbound bootstrap adapter itself still never parses X.509 or
  terminates TLS — by design (see "Wardline never terminates TLS"
  above). It bootstraps *callers* via an already-verified SPIFFE
  identity forwarded by the mesh; the outbound SPIFFE workload identity
  described above is a separate, additive capability, not a change to
  this adapter.
- **No dynamic/live SPIFFE-ID-to-tenant mapping** — the static
  `credentials.yaml` allowlist mirrors the preshared-secret bootstrap
  source's model exactly; there's no pattern-based or trust-domain-based
  automatic mapping.
- **No enforcement, from inside Wardline, that its own network ingress
  path is actually mTLS-only** — same documented-not-enforced posture as
  the existing Ingress-terminates-TLS decision generally.
- Cross-tenant credential-revoke scoping falls back to requiring a
  global `ClusterRoleBinding` grant whenever a target identity name is
  registered under more than one tenant — the same fallback the
  preshared-secret and OIDC bootstrap sources already have, see
  [RBAC](/features/rbac/)'s known limitations.
