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
```

An optional `budget.tenants` override adds a *second*, tenant-keyed
bucket alongside the existing per-identity bucket — a request must
clear **both** to be admitted. A tenant with no override entry is never
checked against a tenant bucket at all; the request falls straight
through to the identity check, unchanged from before per-tenant
overrides existed.

## Known limitations

- Dollar-cost/token-based budgets aren't supported (needs LLM-provider-
  facing traffic, not yet in Wardline's scope).
- In-memory, per-process only — running N replicas gives each replica
  its own independent budget, so the effective limit scales with
  replica count. This is a known, documented limitation, not a bug; see
  [HA deployment](/features/ha-deployment/) for the operational
  consequence.
- One global rate/window pair applies uniformly to every identity — no
  per-tool or tiered budgets yet.
- **A `budget.tenants` override bucket is shared by every identity in
  that tenant, not per-identity.** The identity check and the tenant
  check are an AND, not an OR: one identity that exhausts the tenant's
  shared bucket makes every other identity in that same tenant throttle
  too, for the rest of the window, even if each of those other
  identities is nowhere near its own per-identity limit. This is
  intentional — it's what "the whole tenant gets N requests/window"
  means — but it's easy to misread as a per-identity tenant quota, so
  size `budget.tenants` overrides for the tenant's aggregate traffic,
  not per-identity traffic.
