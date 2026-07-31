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
rbac:
  config_file: "rbac.yaml"
scim:
  bearer_token_env: "WARDLINE_SCIM_TOKEN"   # env var, never inline
  persist_postgres: false                     # requires features.postgres_storage when true
```

Serves `POST`/`GET /scim/v2/Users` and `GET`/`DELETE`/`PATCH
/scim/v2/Users/{id}` (PATCH supports exactly one operation: `{"op":
"replace", "path": "active", "value": true|false}`), plus the same
verb set for `/scim/v2/Groups` (PATCH supports `{"op": "add"|"remove",
"path": "members", "value": [...]}`). Every request needs
`Authorization: Bearer <token>` matching `scim.bearer_token_env`'s
value, compared in constant time: a wrong or missing token gets `401`;
an unknown user/group ID on `GET`/`DELETE`/`PATCH` gets `404`; a
malformed PATCH body gets `400`. A Group's `displayName` encodes the
RBAC grant it provisions: `wardline:tenant-<tenant>:role-<role>` makes
every `active` member a `RoleBinding{Tenant: tenant}`;
`wardline:role-<role>` (no tenant segment) makes every `active` member
a `ClusterRoleBinding` (a global grant, mirroring `rbac.yaml`'s own
no-tenant-means-global convention); any other group name is silently
ignored, so an IdP's non-Wardline groups don't interfere. Bindings
re-derive immediately on every Group PATCH, additive on top of
`rbac.yaml`'s static bindings (checked first), never a replacement.
In-memory by default — provisioned Users/Groups/bindings are lost on
restart; set `scim.persist_postgres: true` (requires
`features.postgres_storage` also on) to persist group→member bindings
in Postgres instead, so a replica restart or a second replica sees the
same bindings.

## Known limitations

- **Not full SCIM 2.0 compliance.** No bulk operations, no
  `/ServiceProviderConfig`/`/Schemas`/`/ResourceTypes` discovery
  endpoints, and only the narrow `?filter=` case real SCIM clients
  (Okta, Azure AD) actually send when checking whether a user/group
  already exists before creating one: `?filter=userName eq "..."` on
  `GET /scim/v2/Users`, `?filter=displayName eq "..."` on `GET
  /scim/v2/Groups`. No general filter grammar — no `and`/`or`, no
  other operators (`ne`, `co`, `sw`, ...), no other fields; any filter
  expression outside this shape is rejected with 400 rather than
  silently answered with the unfiltered list. No filter at all still
  returns the full list, unchanged. Only the PATCH operations named
  above are recognized; every other operation or path is silently
  ignored, not rejected.
- The `and`/`or`-combinator rejection above is a substring heuristic,
  not a grammar parse: a legitimate `userName`/`displayName` value that
  genuinely contains the space-padded substring `" and "` or `" or "`
  (e.g. `"Sam and Dave Fan Club"`) is incorrectly rejected with 400,
  since the filter parser can't distinguish that from an actual SCIM
  `and`/`or` combinator without a real grammar tokenizer — deliberately
  out of scope for the narrow eq-only support above.
- **A global SCIM group (`wardline:role-<role>`, no tenant segment)
  grants across every tenant's same-named identity, not just one.**
  SCIM `Group` members are bare `userName`s with no tenant segment, and
  the resulting `ClusterRoleBinding{Subject: identity}` is, by
  definition, checked against every tenant — consistent with
  `rbac.yaml`'s own no-tenant-means-global convention, but worth
  calling out explicitly now that identity names are legitimately
  per-tenant-unique (see [Credential issuance](/features/credential-issuance/)):
  a global grant to `alice` reaches acme's `alice` and widgets-inc's
  `alice` alike, even if only one of them was meant to have it.
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
