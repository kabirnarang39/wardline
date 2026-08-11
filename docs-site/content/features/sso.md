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
  identities_file: "credentials.yaml"   # still required even for oidc -- see note below
  bootstrap_source: "oidc"        # "presharedsecret" (default) | "oidc" | "mtls"
  oidc:
    issuer: "https://idp.example.com/"
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    audience: "wardline"
    identity_claim: "sub"          # optional, default "sub"
    tenant_claim: "tenant"         # optional, default "tenant" -- required present on every token
```

`credential.identities_file` is required whenever `features.credential_issuance`
is on, regardless of `bootstrap_source` — a non-obvious quirk worth calling
out: even when every identity comes from the IdP via `oidc`, config
validation still requires this path to be set (it's simply unused by the
OIDC bootstrapper itself).

### More than one IdP: `oidc_providers`

`credential.oidc` (above) configures exactly one issuer. For more than
one — a real multi-tenant deployment where different tenants federate
through different IdPs — use `credential.oidc_providers` instead (mutually
exclusive with `oidc`; setting both is a config error):

```yaml
credential:
  identities_file: "credentials.yaml"
  bootstrap_source: "oidc"
  oidc_providers:
    - issuer: "https://acme.okta.com/"
      audience: "wardline"
      tenant_claim: "tenant"          # acme's tokens carry their own tenant claim
    - issuer: "https://login.microsoftonline.com/widgets-inc/v2.0"
      audience: "wardline"
      tenant_claim: "tid"             # widgets-inc's IdP names its tenant claim differently
```

Each entry is independently verified — its own JWKS (or discovery, same
`jwks_uri`-optional rule as the single-provider form above), its own
`audience`, its own `identity_claim`/`tenant_claim`. An incoming ID
token is routed to the right provider by its own `iss` claim before
verification — the same issuer-based routing every real multi-tenant
SSO gateway uses (Auth0's multi-organization routing, Okta's multi-IdP
routing rules, Azure AD B2C's identity-provider selection): the router
only reads that one claim to pick which provider's `Authenticate` runs
next, and that provider still fully re-verifies the token's signature
against its own real JWKS and re-checks the issuer itself — a token
whose `iss` claim doesn't match the key that actually signed it is
rejected exactly as it would be without multi-provider routing at all.
Two providers may not declare the same issuer (ambiguous routing,
rejected at config-validate time, not a runtime coin flip).

`Authenticate` verifies the token's signature against `jwks_uri` (keys
cached and refreshed every 15 minutes), checks `iss`/`aud`/`exp`, then
reads `identity_claim` (`sub` by default) and `tenant_claim` for the
resolved identity and tenant. Any failure — bad signature, wrong
issuer/audience, expired token, or a missing/empty tenant claim — is a
generic `401`, the same non-enumerable-failure posture as a rejected
preshared secret.

`wardline validate-config` attempts to construct the OIDC bootstrapper
when `bootstrap_source: oidc` — the same construction `wardline serve`
itself does at startup. The underlying JWKS client
(`lestrrat-go/jwx/v3/jwk.Cache`) waits for its first successful fetch,
but that wait is bounded by a 10-second internal timeout: an
unreachable, refused, 404, or otherwise-broken `jwks_uri` produces the
intended soft warning at validate time (or `serve`'s intended fail-fast
exit) within that bound rather than hanging.

## Known limitations

- `issuer` and `audience` must be configured explicitly. `jwks_uri` is
  optional — leave it unset and Wardline resolves it at startup from
  `issuer`'s own `/.well-known/openid-configuration` discovery document
  (standard OIDC discovery, every major IdP implements it), validating
  the document's own `issuer` field matches before trusting its
  `jwks_uri`. Set `jwks_uri` explicitly to skip discovery entirely — an
  IdP with a non-standard or unreachable discovery endpoint, or an
  operator who prefers to pin the value.
- Cross-tenant credential-revoke scoping falls back to requiring a
  global `ClusterRoleBinding` grant for every revoke when this
  bootstrap source is active — and the same fallback also applies to the
  preshared-secret bootstrap source whenever a target identity name is
  registered in more than one tenant — see [RBAC](/features/rbac/)'s
  known limitations.
