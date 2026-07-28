---
title: "Budget Enforcement"
weight: 40
summary: "Per-identity request-rate limiting."
---

A per-identity request-rate limiter (requests per window), enforced
before a call reaches policy evaluation. Enable with:

```yaml
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
```

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
