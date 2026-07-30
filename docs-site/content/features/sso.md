---
title: "SSO"
weight: 25
summary: "OIDC ID-token bootstrap for Wardline's own admin identity and tenant."
---

A second [Credential Issuance](/features/credential-issuance/) bootstrap
adapter: instead of a preshared secret matched against
`credentials.yaml`, the presented secret is treated as a raw OIDC ID
token, verified against an IdP's JWKS. Unlike a `credentials.yaml`
entry (which defaults to tenant `"default"` when it omits one), an
SSO-sourced identity's tenant has no default — a token missing the
configured tenant claim is rejected outright, not silently placed in
`"default"`.

There is no separate `sso` feature flag — enable it by pointing
`credential_issuance`'s existing bootstrap source at `oidc`:

```yaml
features:
  credential_issuance: true
credential:
  bootstrap_source: "oidc"        # "presharedsecret" (default) | "oidc"
  oidc:
    issuer: "https://idp.example.com/"
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    audience: "wardline"
    identity_claim: "sub"          # optional, default "sub"
    tenant_claim: "tenant"         # optional, default "tenant" -- required present on every token
```

`Authenticate` verifies the token's signature against `jwks_uri` (keys
cached and refreshed every 15 minutes), checks `iss`/`aud`/`exp`, then
reads `identity_claim` (`sub` by default) and `tenant_claim` for the
resolved identity and tenant. Any failure — bad signature, wrong
issuer/audience, expired token, or a missing/empty tenant claim — is a
generic `401`, the same non-enumerable-failure posture as a rejected
preshared secret.

`wardline validate-config` attempts to construct the OIDC bootstrapper
when `bootstrap_source: oidc` (checks the config is well-formed); a
JWKS endpoint that's unreachable at validate time is a warning, not a
hard failure, since the JWKS cache retries at runtime.

## Known limitations

- **No OIDC discovery document fetching** — `issuer`, `jwks_uri`, and
  `audience` must be configured explicitly; nothing is resolved from
  `/.well-known/openid-configuration`.
- **One IdP at a time** — a single `credential.oidc` block; no
  multiple-issuer or issuer-to-tenant mapping.
- Cross-tenant credential-revoke scoping falls back to requiring a
  global `ClusterRoleBinding` grant for every revoke when this
  bootstrap source is active — see [RBAC](/features/rbac/)'s known
  limitations.
- No refresh tokens or configurable JWT TTL — same limitation as
  [Credential Issuance](/features/credential-issuance/) generally.
