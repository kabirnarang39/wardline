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

## Known limitations

- Dollar-cost/token-based budgets aren't supported (needs LLM-provider-
  facing traffic, not yet in Wardline's scope).
- In-memory, per-process only — running N replicas gives each replica
  its own independent budget, so the effective limit scales with
  replica count. This is a known, documented limitation, not a bug; see
  [HA deployment](/features/ha-deployment/) for the operational
  consequence.
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
