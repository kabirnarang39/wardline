---
title: "RBAC"
weight: 30
summary: "Role-based access to Wardline's own admin surface."
---

Role-based access control for Wardline's own admin capabilities (not a
replacement for the tool-call policy engine — this governs who can
manage Wardline itself). Enable with:

```yaml
features:
  rbac: true
rbac:
  config_file: "rbac.yaml"
```

Tenant isolation is real: every `Authorize`/`IsGlobal` call is fed the
caller's actual resolved tenant (from the active identity source, not a
hardcoded literal), and a `RoleBinding` only grants within the tenant it
names. A `ClusterRoleBinding` (no `tenant:` in `rbac.yaml`, or a SCIM
group named `wardline:role-<role>` with no tenant segment) still grants
globally, across every tenant — the "no tenant means global" convention
`rbac.yaml` and SCIM group naming both share.

## Known limitations

- File-based role/binding management (`rbac.yaml`) is still the only
  static source — SCIM-provisioned bindings (see [SCIM](/features/scim/))
  are additive on top, not a replacement.
- When `credential.bootstrap_source: oidc`, cross-tenant credential-revoke
  scoping (see [SSO](/features/sso/)) falls back to requiring a global
  `ClusterRoleBinding` grant for every revoke — the OIDC bootstrapper has
  no static identity registry to look up an arbitrary target identity's
  tenant from after the fact, unlike the preshared-secret bootstrapper.
- **Credential revocation itself is keyed by identity name only, not
  `(tenant, identity)`** — see [Credential issuance](/features/credential-issuance/)'s
  known limitations for the full explanation. The revoke *authorization*
  check above (whether a caller may revoke a given target) is correctly
  tenant-scoped; the underlying revoked-identities store it feeds into is
  not, so an authorized, correctly-scoped revoke of your own tenant's
  `alice` currently revokes every tenant's `alice`.
- Federation's correlated-alerts view is not tenant-scoped — it
  correlates on an identity fingerprint computed locally, and making
  that tenant-aware is a separate, not-yet-scheduled change (federation
  has no dedicated docs page yet).
- Does not require `credential_issuance` — composes with whatever
  identity source is active, and is only as strong as whatever
  authenticates that identity.
