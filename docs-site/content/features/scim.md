---
title: "SCIM"
weight: 35
summary: "SCIM-shaped Users/Groups provisioning that maps IdP group membership to RBAC role bindings."
---

An IdP-driven provisioning API for [RBAC](/features/rbac/): SCIM Groups
map to `RoleBinding`s (or `ClusterRoleBinding`s) automatically, so a
group added or edited in Okta/Azure AD/Google Workspace takes effect in
Wardline with no `rbac.yaml` edit. Enable with:

```yaml
features:
  scim: true
  rbac: true                # SCIM provisions bindings for RBAC to consult
scim:
  bearer_token_env: "WARDLINE_SCIM_TOKEN"   # env var, never inline
  persist_postgres: false                     # requires features.postgres_storage when true
```

## Endpoints

- `POST /scim/v2/Users`, `GET /scim/v2/Users` — create / list.
- `GET`, `DELETE`, `PATCH /scim/v2/Users/{id}` — read, delete, and a
  PATCH that supports exactly one operation: `{"op": "replace", "path":
  "active", "value": true|false}` (any other op or path is ignored).
- `POST /scim/v2/Groups`, `GET /scim/v2/Groups` — create / list.
- `GET`, `DELETE`, `PATCH /scim/v2/Groups/{id}` — read, delete, and a
  PATCH that supports exactly two operations, both on `"path":
  "members"`: `{"op": "add", "value": [...]}` and `{"op": "remove",
  "value": [...]}`.
- Every request needs `Authorization: Bearer <token>` matching
  `scim.bearer_token_env`'s value, compared in constant time. A wrong
  or missing token gets a `401` in an RFC 7644-shaped error body;
  an unknown user/group ID gets `404`; a malformed PATCH body gets
  `400`.

## Group name is the tenant/role carrier

A Group's `displayName` encodes the RBAC grant it provisions:

- `wardline:tenant-<tenant>:role-<role>` — every `active` member becomes
  a `RoleBinding{Subject: member, RoleName: role, Tenant: tenant}`.
- `wardline:role-<role>` (no tenant segment) — every `active` member
  becomes a `ClusterRoleBinding` (a global grant, mirroring
  `rbac.yaml`'s own no-tenant-means-global convention).
- Any other group name is silently ignored — an IdP's non-Wardline
  groups must not error or interfere with provisioning.

Membership changes go through immediately: `PATCH .../Groups/{id}`
re-derives that group's bindings on every add/remove. SCIM-provisioned
bindings are additive on top of `rbac.yaml`'s static bindings (checked
first), never a replacement for them.

## Persistence

In-memory by default — provisioned Users/Groups/bindings are lost on
restart. Set `scim.persist_postgres: true` (requires
`features.postgres_storage` also on) to persist group→member bindings
in Postgres instead, so a replica restart or a second replica sees the
same bindings.

## Known limitations

- **Not full SCIM 2.0 compliance.** No bulk operations, no
  `/ServiceProviderConfig`/`/Schemas`/`/ResourceTypes` discovery
  endpoints, and no `?filter=` query support at all — `GET
  /scim/v2/Users` and `GET /scim/v2/Groups` always return the full
  list; the adapter doesn't parse a `filter` query parameter, not even
  the narrow `userName eq "..."` / `displayName eq "..."` case. Only
  the PATCH operations named above are recognized; every other
  operation or path is silently ignored, not rejected.
- Users track only `userName` and `active` — no name, email, or other
  SCIM User attributes.
- A single shared bearer token, not per-client credentials or OAuth —
  same shared-secret trust model as `federation.peers_file`'s signing
  keys and preshared-secret credential bootstrap.
- `persist_postgres`'s failure mode is fail-closed for authorization:
  a Postgres read error returns no SCIM-provisioned bindings for that
  request rather than serving stale cached ones, so a database outage
  can make a SCIM-only grant (one with no `rbac.yaml` equivalent)
  temporarily unauthorized.
- No UI for SCIM/tenant management — provisioning is API/IdP-driven
  only, same posture as every other admin-surface feature in this
  project.
