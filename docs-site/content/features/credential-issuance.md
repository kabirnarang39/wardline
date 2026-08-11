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
  oidc`, with optional discovery-document fetching — see
  [SSO](/features/sso/)). No other IdP protocol (SAML, generic non-OIDC
  federation) is
  supported, and mTLS/SPIFFE bootstrap (`credential.bootstrap_source:
  mtls`) trusts a single static header — see [mTLS/SPIFFE
  Bootstrap](/features/mtls-bootstrap/) for its trust-boundary
  requirements before enabling it.
- Refresh tokens rotate with **reuse detection and family revocation**:
  each bootstrap starts a token *family*, every rotation carries it
  forward, and a redeemed token is kept (marked consumed) rather than
  deleted so a later replay is detectable. Replaying an
  already-consumed token is treated as a theft signal — the entire
  family (the legitimate current token included) is revoked atomically,
  a `SECURITY: refresh token reuse detected` line is logged, and the
  caller gets the same generic `401` as any other rejection (no oracle).
  The one residual: access tokens already minted in that family are not
  force-revoked on reuse; they expire on their own short TTL
  (`access_token_ttl_seconds`, default 15m).
- Revocation state is per-process unless `postgres_storage` is also on
  (see [HA deployment](/features/ha-deployment/)).
- **Revocation is keyed by `(tenant, identity)`, with one residual
  wildcard gap, narrowable by the caller.** Identity names are
  per-tenant-unique (two different IdPs or two `credentials.yaml`
  entries can legitimately both provision "alice", one per tenant); the
  revocation store (`RevocationList`/`PostgresRevoker`, and the
  `Revoker.IsRevoked` call in `VerificationService.Authenticate`) scopes
  both the write and the check to the target identity's own tenant,
  resolved at revoke time — no Postgres schema migration needed
  (`PostgresRevoker` encodes `(tenant, identity)` into its existing
  `identity` primary-key column via a length-prefixed key rather than
  adding a column). When a target identity's tenant cannot be resolved
  at revoke time (OIDC bootstrap source with no static registry, or an
  identity name registered under two or more distinct tenants —
  `Bootstrapper.TenantOf` and `MTLSBootstrapper.TenantOf` both
  deliberately fail closed to "unresolved" on that ambiguity, rather
  than guessing which tenant's copy to scope to), reaching this branch
  at all already requires the caller to hold a **global**
  `credential:revoke` grant (see [RBAC](/features/rbac/) —
  `newRevokeAuthorizer` denies a tenant-scoped caller outright when the
  target's tenant can't be resolved). `POST /credentials/revoke` accepts
  an optional `tenant` field in the request body for exactly this case:
  a caller who already knows which tenant they mean can name it, and
  the revoke is scoped to that one tenant instead of every tenant's
  copy of the identity name. Omitting `tenant` preserves the old,
  full-wildcard behavior unchanged — this is an added precision option,
  not a required migration. The registry is still authoritative
  whenever it *can* resolve a tenant: a client-supplied `tenant` is
  ignored, never allowed to override a resolved value.
