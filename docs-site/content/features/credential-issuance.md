---
title: "Credential Issuance"
weight: 20
summary: "Short-lived, RS256-signed identity tokens with revocation."
---

Issues short-lived RS256-signed JWTs to agents bootstrapping against
Wardline, instead of trusting a raw `X-Wardline-Identity` header alone.
Enable with:

```yaml
features:
  credential_issuance: true
credential:
  identities_file: "identities.yaml"
  signing_key_file: ""              # optional; see HA deployment for why this matters with >1 replica
  access_token_ttl_seconds: 900     # optional, default 900 (15m)
  refresh_token_ttl_seconds: 86400  # optional, default 86400 (24h)
```

Tokens can be revoked; revocation is checked on every request.

`POST /credentials/token` returns both an access token and a refresh
token. `POST /credentials/refresh {"refresh_token": "..."}` exchanges a
still-valid, not-yet-used refresh token for a new pair of both --
without re-presenting the original bootstrap credential -- until the
refresh token itself expires or its identity is revoked. Refresh tokens
are single-use: each successful refresh rotates to a brand-new refresh
token, and the one just redeemed can never be used again.

## Known limitations

- IdP-backed bootstrap is OIDC only (`credential.bootstrap_source:
  oidc`, no discovery-document fetching) — see [SSO](/features/sso/).
  No other IdP protocol (SAML, generic non-OIDC federation) is
  supported, and mTLS/SPIFFE bootstrap (`credential.bootstrap_source:
  mtls`) trusts a single static header — see [mTLS/SPIFFE
  Bootstrap](/features/mtls-bootstrap/) for its trust-boundary
  requirements before enabling it.
- Refresh-token reuse is rejected the same as any other invalid token,
  but there's no reuse-DETECTION signal or cascading family revocation
  (a real theft-response mechanism some OAuth2 implementations add) --
  a stolen-and-already-used refresh token simply fails the same generic
  way an expired or never-issued one does, with no extra alert.
- Revocation state is per-process unless `postgres_storage` is also on
  (see [HA deployment](/features/ha-deployment/)).
- **Revocation is keyed by `(tenant, identity)`, with one residual
  wildcard gap.** Identity names are per-tenant-unique (two different
  IdPs or two `credentials.yaml` entries can legitimately both provision
  "alice", one per tenant); the revocation store
  (`RevocationList`/`PostgresRevoker`, and the `Revoker.IsRevoked` call in
  `VerificationService.Authenticate`) now scopes both the write and the
  check to the target identity's own tenant, resolved at revoke time —
  no Postgres schema migration needed (`PostgresRevoker` encodes
  `(tenant, identity)` into its existing `identity` primary-key column
  via a length-prefixed key rather than adding a column). The gap that
  remains: when a target identity's tenant cannot be resolved at revoke
  time, the revoke falls back to the pre-scoping wildcard behavior —
  revoking every tenant's copy of that identity name at once, the same
  as before this cycle's fix. This is not an OIDC-only gap: it's
  reachable under **any** of the three bootstrap sources. With
  `bootstrap_source: oidc`, tenant lookup always fails (no static
  identity registry exists to look a target up in). With the
  preshared-secret and mtls bootstrappers, lookup normally succeeds
  from `credentials.yaml` — but fails the same way whenever the target
  identity name (preshared-secret) or its mapped SPIFFE ID's identity
  (mtls) is registered under two or more distinct tenants
  (`Bootstrapper.TenantOf` and `MTLSBootstrapper.TenantOf` both
  deliberately fail closed to "unresolved" on that ambiguity, rather
  than guessing which tenant's copy to scope to) — precisely the "two
  `credentials.yaml` entries legitimately provision the same name"
  scenario described above. A caller holding a global
  `credential:revoke` grant (see [RBAC](/features/rbac/)) can trigger
  this wildcard fallback under any bootstrap source, with no OIDC
  involved.
