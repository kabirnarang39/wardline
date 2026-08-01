---
title: "Budget Enforcement"
weight: 40
summary: "Per-identity request-rate limiting."
---

A per-identity request-rate limiter (requests per window), enforced
before a call reaches policy evaluation. A throttled call gets HTTP 429
and is recorded in the audit log with decision `throttled` (see
[Audit Log](/concepts/audit-log/)). Enable with:

```yaml
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    acme:
      requests_per_window: 1000
      window_seconds: 60
  tools:
    expensive_tool:
      requests_per_window: 10
      window_seconds: 60
```

An optional `budget.tenants` override adds a *second*, tenant-keyed
bucket alongside the existing per-identity bucket — a request must
clear **both** to be admitted. A tenant with no override entry is never
checked against a tenant bucket at all; the request falls straight
through to the identity check, unchanged from before per-tenant
overrides existed.

An optional `budget.tools` override adds a *third* bucket, keyed by the
MCP tool name being called, on top of the identity and tenant buckets —
a request must clear all three configured buckets to be admitted. Order
is tool, then tenant, then identity: whichever bucket denies first
never consumes budget from the buckets that would have run after it. A
tool with no override entry is never checked against a tool bucket at
all, same "absent means unchanged" behavior as `budget.tenants`. Both
`tenants` and `tools` share the same shape (`requests_per_window`,
`window_seconds`) as the top-level default; only one level of nesting
under each is wired up.

When `features.postgres_storage` is also on, budget enforcement is
backed by a shared Postgres table instead of an in-process map — every
replica connected to the same database enforces the same identity/
tenant/tool buckets, so the effective limit no longer scales with
replica count. No separate config flag: the same `budget:` block above
applies unchanged, only the storage backend changes.

**Postgres-backed checks fail open.** If the database query errors or
times out (5-second bound per check), the call is admitted rather than
rejected — availability over enforcement, the same posture credential
revocation takes. A fail-open decision is not silent: it logs a warning
*and* records the audit entry with decision `allow` and a reason of
`budget check failed open: <cause>`, where an ordinary allow records an
empty reason. Alert on that reason if you need to know when enforcement
was skipped — `/readyz` only pings Postgres, so it stays green through
the query-level failures that cause this.

## Known limitations

- Dollar-cost/token-based budgets aren't supported (needs LLM-provider-
  facing traffic, not yet in Wardline's scope).
- **In-memory by default, per-process only** — running N replicas gives
  each replica its own independent budget, so the effective limit
  scales with replica count, UNLESS `features.postgres_storage` is also
  on: budget enforcement then shares one Postgres-backed counter across
  every replica, the same way credential revocation and refresh tokens
  already do. See [HA deployment](/features/ha-deployment/) and
  [Credential issuance](/features/credential-issuance/)'s sibling
  Postgres-backed features for the general pattern.
- **A `budget.tenants` or `budget.tools` override bucket is shared by
  every identity (or every call to that tool) that hits it, not
  per-identity.** Every configured bucket is an AND, not an OR: one
  identity that exhausts a shared tenant or tool bucket makes every
  other identity sharing that bucket throttle too, for the rest of the
  window, even if each of those other identities is nowhere near its own
  per-identity limit. This is intentional — it's what "the whole tenant"
  or "this tool gets N requests/window" means — but it's easy to misread
  as a per-identity quota, so size `budget.tenants`/`budget.tools`
  overrides for the bucket's aggregate traffic, not per-identity
  traffic.
- **Postgres-backed budget checks compete for connections with every
  other Postgres-backed feature.** Each tier is its own round trip, so a
  single request can cost up to three (tool, tenant, identity) when both
  override kinds are configured. Every Postgres-backed feature — audit,
  revocation, refresh tokens, SCIM, anomaly baselines, and the limiter —
  manages its own independent connection pool rather than sharing one, so
  a replica with `postgres_storage` on can hold tens of connections
  against a database whose default `max_connections` is often 100. Under
  sustained load beyond the available connections, a budget check blocks
  waiting for a connection, hits its 5-second timeout, and **fails open**
  (see the fail-open behavior above) rather than enforcing the limit —
  meaning the harder the load spike, the more likely enforcement is
  skipped. Size your pools and `max_connections` for the number of
  replicas × Postgres-backed features you actually run; a single shared
  pool across features is a candidate for a future cycle.
