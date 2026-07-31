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
  signing_key_file: ""   # optional; see HA deployment for why this matters with >1 replica
```

Tokens can be revoked; revocation is checked on every request.

## Known limitations

- No mTLS/SPIFFE-style X.509-SVID bootstrap yet — designed for
  (`domain.Bootstrapper` is the seam), not built.
- IdP-backed bootstrap is OIDC only (`credential.bootstrap_source:
  oidc`, no discovery-document fetching) — see [SSO](/features/sso/).
  No other IdP protocol (SAML, generic non-OIDC federation) is
  supported.
- No refresh tokens — rotation model is re-bootstrap with the same
  registration secret before expiry.
- Revocation state is per-process unless `postgres_storage` is also on
  (see [HA deployment](/features/ha-deployment/)).
- JWT TTL is a single fixed constant, not yet operator-configurable.
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
  time (OIDC bootstrap has no static identity registry to look it up
  from), the revoke falls back to the pre-scoping wildcard behavior —
  revoking every tenant's copy of that identity name at once, the same
  as before this cycle's fix. This only affects the OIDC bootstrap
  source; the preshared-secret bootstrapper always resolves a target's
  tenant from `credentials.yaml`.
