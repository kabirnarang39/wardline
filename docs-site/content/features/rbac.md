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
  `ClusterRoleBinding` grant for *every* revoke — the OIDC bootstrapper
  has no static identity registry to look up an arbitrary target
  identity's tenant from after the fact. The preshared-secret
  bootstrapper normally resolves a target's tenant from
  `credentials.yaml` and doesn't need this fallback — except for the
  same edge case as [Credential issuance](/features/credential-issuance/)'s
  revocation-keying gap: an identity name registered under two or more
  distinct tenants resolves ambiguously there too, so a scoped (non-global)
  caller revoking that name is denied and a global grant is required,
  same as OIDC.
- Credential revocation is now genuinely `(tenant, identity)`-keyed (see
  [Credential issuance](/features/credential-issuance/)'s known
  limitations for the residual gap: a revoke whose target tenant cannot
  be resolved still falls back to a wildcard revoke across every tenant's
  copy of that identity name).
- Federation's correlated-alerts view is not tenant-scoped — it
  correlates on an identity fingerprint computed locally, and making
  that tenant-aware is a separate, not-yet-scheduled change (federation
  has no dedicated docs page yet).
- Does not require `credential_issuance` — composes with whatever
  identity source is active, and is only as strong as whatever
  authenticates that identity.
