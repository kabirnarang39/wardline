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
/scim/v2/Users/{id}` (PATCH takes a SCIM 2.0 `Operations` array and
supports exactly one operation: `{"Operations": [{"op": "replace",
"path": "active", "value": true|false}]}`), plus the same verb set for
`/scim/v2/Groups` (PATCH supports `{"Operations": [{"op":
"add"|"remove", "path": "members", "value": [...]}]}`), `POST
/scim/v2/Bulk` (RFC 7644 §3.7 — batches Create/PATCH/Delete operations
against `/Users`/`/Groups` in one request, each dispatched through the
exact same handler logic the individual endpoints use), and the
discovery triad every real SCIM client probes before provisioning
anything: `GET /scim/v2/ServiceProviderConfig`, `GET
/scim/v2/ResourceTypes`(`/{id}`), `GET /scim/v2/Schemas`(`/{id}`) — each
describing what this server actually supports, not a boilerplate
template. Every request needs `Authorization: Bearer <token>` matching `scim.bearer_token_env`'s
value, compared in constant time: a wrong or missing token gets `401`;
an unknown user/group ID on `GET`/`DELETE`/`PATCH` gets `404`; a
malformed PATCH body — including one missing the `Operations` wrapper or
naming no supported operation — gets `400` (never a silent `204`, so a
deactivation can't report success without applying). A Group's `displayName` encodes the
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

- **`?filter=` now parses a real SCIM filter grammar** (RFC 7644
  §3.4.2.2 — tokenizer + recursive-descent parser + AST evaluator, not
  a pattern-matched special case): every comparison operator (`eq`,
  `ne`, `co`, `sw`, `ew`, `gt`, `lt`, `ge`, `le`, `pr`), `and`/`or`/`not`
  with parentheses, against any attribute the resource actually has
  (`userName`/`active` on Users, `displayName` on Groups). A filter
  naming an attribute the resource type doesn't have simply never
  matches (an empty list), not a 400 — filtering on a schema-valid but
  absent attribute isn't a syntax error. Only genuinely malformed syntax
  (unterminated string, unknown operator, unbalanced parens) gets 400.
  Only the PATCH operations documented above are recognized; every
  other operation or path is silently ignored, not rejected.
- **Bulk operations execute independently — no cross-operation `bulkId`
  substitution** (RFC 7644 §3.7.2's `"bulkId:<id>"` reference syntax,
  letting a later operation in the same batch reference an earlier
  operation's not-yet-known resource ID). This is the shape real SCIM
  clients actually generate for bulk User/Group provisioning
  (independent Create operations against a stable target); a client
  that needs to reference a just-created resource's ID within the same
  batch must split it across two Bulk requests instead.
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
