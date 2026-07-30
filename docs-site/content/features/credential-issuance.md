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
