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
- **Revocation is keyed by identity name only, not `(tenant, identity)`.**
  This branch made identity names per-tenant-unique (two different IdPs
  or two `credentials.yaml` entries can legitimately both provision
  "alice", one per tenant), and re-keyed anomaly detection and budget
  enforcement to match — but the revocation store
  (`RevocationList`/`PostgresRevoker`, and the `Revoker.IsRevoked` call
  in `VerificationService.Authenticate`) was not. The revoke
  *authorization* check (does this caller have permission to revoke this
  target — see [RBAC](/features/rbac/)) is correctly tenant-scoped; the
  store it writes into is not. In practice: acme's admin, legitimately
  and correctly authorized, revokes acme's `alice` — and widgets-inc's
  `alice`, an entirely different identity that acme's admin has no
  authority over, is also revoked. Fixing this needs a Postgres primary
  key change (from `identity` alone to `(tenant, identity)`, not a purely
  additive column) plus a fallback design for the cases where a target
  identity's tenant cannot be resolved at revoke time (OIDC bootstrap has
  no static identity registry to look it up from; an identity name
  registered in more than one tenant is deliberately ambiguous, see
  above) — both meaningfully larger and riskier than this cycle's other
  fixes, so it is being tracked as a known limitation rather than shipped
  as a rushed migration.
