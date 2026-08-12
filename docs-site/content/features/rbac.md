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
- **The RBAC dashboard view (and its `GET /dashboard/api/rbac`
  endpoint) lists only `rbac.yaml`'s static bindings.** SCIM-provisioned
  bindings are fully enforced (a SCIM-derived role grants real
  permissions on every request, verified end to end) but never appear
  in this list or in a role's `binding_count`. The gap is structural,
  not an oversight to patch: `CompositeAuthorizer` (what actually
  authorizes a request once SCIM is on) only asks its dynamic source
  "what bindings does *this one identity* have," the lookup shape
  enforcement needs — it has no "list every binding that currently
  exists" operation, which is what a display would need instead.
  Adding that is a real new capability (touching the SCIM binding
  store's interface and both its in-memory and Postgres
  implementations), not a rewire.
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
  limitations: a revoke whose target tenant cannot be resolved still
  defaults to a wildcard revoke across every tenant's copy of that
  identity name, but a caller who already holds the global grant this
  path requires can pass an explicit `tenant` to scope it to one tenant
  instead).
- Federation's correlated-alerts view is now tenant-scoped, same as
  every other dashboard view — see [Federation](/features/federation/)'s
  own known limitations for what's still instance-scoped (each
  Wardline instance's own `Correlator`, not merged fleet-wide).
- Does not require `credential_issuance` — composes with whatever
  identity source is active, and is only as strong as whatever
  authenticates that identity.
