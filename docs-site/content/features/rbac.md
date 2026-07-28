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

## Known limitations

- Single-tenant only — `RoleBinding`'s tenant field is real and
  consulted, but every caller resolves against the one implicit tenant
  `"default"`; there is no isolation *by* tenant yet.
- File-based role/binding management only — no HTTP API for managing
  roles/bindings.
- No SSO/SCIM — the admin identity still comes from whatever identity
  source is active (preshared-secret bootstrap or the raw header), not
  an IdP. SSO/SCIM is an explicit v2.0 roadmap item.
- Does not require `credential_issuance` — composes with whatever
  identity source is active, and is only as strong as whatever
  authenticates that identity.
