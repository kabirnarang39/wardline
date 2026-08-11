---
title: "Per-Job Cost/Token Budget"
weight: 58
summary: "A hard cap on total declared cost per (tenant, identity, session), not just call count — catches a job that's expensive per call, not just one that calls a lot."
---

[Per-job budget ceiling]({{< relref "job-budget" >}}) caps the *count* of
calls in a job — every call is worth exactly 1, regardless of what it
actually does. That's blind to a job that stays well under any request-count
cap while burning real money: ten calls to a cheap `read_file` tool and ten
calls to an expensive `run_llm_completion` tool trip the same counter by the
same amount, even though one job is orders of magnitude more expensive than
the other. Per-job cost/token budget assigns each tool a declared cost and
caps the *total* of those costs per job — the same `(tenant, identity,
session)` job concept, a different unit.

Enable with:

```yaml
features:
  job_cost_budget: true
job_cost_budget:
  ceiling: 1000              # optional -- defaults to 1000 when unset
  tool_costs:                # optional -- per-tool declared cost
    run_llm_completion: 50
    read_file: 1
  default_cost: 1             # optional -- cost for a tool not in tool_costs; defaults to 1
```

## Sessions

A "job" is the same `(tenant, identity, session)` triple [taint
tracking]({{< relref "taint-tracking" >}}) established and [per-job budget
ceiling]({{< relref "job-budget" >}}) reuses — the explicit
`X-Wardline-Session` header when the agent framework stamps one per run, or
a per-identity sliding TTL window as a fallback when it doesn't. See [Taint
tracking → Sessions]({{< relref "taint-tracking#sessions" >}}) for the exact
mechanics. Cost budget's counters live in their own store, never shared with
job budget's — the two features never read or write the same key, even
though both key on the identical triple.

## Declared cost, not measured usage

Each gated tool call has a declared cost, looked up from `tool_costs` by
tool name; a tool absent from `tool_costs` falls back to `default_cost`
(itself defaulting to 1 when unset). An explicit `0` for a declared tool is
honored as a genuinely free call, not treated as "unset". This is a static
table an operator writes, not a measurement of what a call actually did —
see the boundary section below.

## Two consumption points

1. **A hard proxy gate, always on when the flag is on.** Every gated call
   adds its declared cost to the job's running total; a call that would push
   the total *past* `ceiling` (strictly greater than, not equal) gets `429`
   and is **not forwarded upstream**. The audit entry records decision
   `cost_budget_exceeded` — a distinct value from both `throttled` (budget
   enforcement's rate-limit decision) and `job_budget_exceeded` (per-job
   request-count), so all three enforcement dimensions stay individually
   greppable in the audit trail rather than collapsing into one signal.

2. **An optional `input.cost_over_budget` field in Rego**, mirroring
   `input.job_over_budget`. A hard 429 is the simplest outcome; pairing
   `cost_over_budget` with `approval` instead routes the over-budget job
   through [approval workflow]({{< relref "approval-workflow" >}}) — an
   operator sees it and decides whether to let it continue, rather than a
   flat block:

   ```rego
   package wardline.authz

   default allow = false

   approval {
     input.cost_over_budget
   }

   allow {
     input.identity == "agent-abc123"
   }
   ```

   See the [Rego reference]({{< relref "policy-rego-reference" >}}) for the
   full result contract. `input.cost_over_budget` is read-only from a
   policy's perspective: consulting it never adds to the job's total — only
   the hard gate above does that, exactly once per request, so a policy that
   checks the field on every evaluation can't itself trip the ceiling.

## Grant-override

An approved retry is admitted **even over the cost ceiling.** Cost budget
shares its grant-carve-out with the per-job request-count gate: when
`approval_workflow` is on and an operator approves a held call, the
single-use grant that admits the retry overrides every ceiling dimension the
`needs_approval` routing could have tripped — cost budget, job budget, or
both at once — not just whichever policy field happened to trigger the hold.
The operator approved *the call*, not one specific objection to it. Outside
that narrow, one-call carve-out, every other caller still hits the hard
`cost_budget_exceeded` deny. The job's running total still accumulates the
grant-admitted call's cost, so the ceiling stays accurate for every
subsequent call on that job — only this one call is let through, not the
ceiling itself.

## Boundary — what this is and isn't

- **A static per-tool cost table, not measured usage.** `tool_costs` is a
  number an operator writes ahead of time per tool name. Nothing in this
  feature parses a response body, a token-usage field, or any other
  upstream-reported signal — the declared cost is charged whether the call
  actually used that much or not. If a tool's real cost varies per call
  (e.g. a completion whose token count depends on the prompt), the declared
  number is a flat estimate, not a per-call measurement.
- **No real-money billing.** The ceiling and the per-tool costs are
  whatever unit the operator chooses (tokens, an arbitrary weight, dollars
  as a mental model) — there's no currency conversion, no invoice, no
  connection to a billing system. It's an internal accounting number for
  enforcement, not a financial record.
- **No cross-job or cross-identity aggregation.** Same as per-job budget
  ceiling: the ceiling is scoped to one job — one `(tenant, identity,
  session)`. Ten sessions each just under `ceiling` is nowhere near any
  limit this feature enforces; it isn't a fleet-wide or per-identity total.
- **No manual reset.** There's no reset endpoint or admin action that
  clears a job's running total mid-session. The ceiling holds until the
  session itself rotates — the header value changes, or (in fallback mode)
  the TTL window lapses — the same boundary that ends taint's session and
  per-job budget's.
- **The dashboard's cost-budget view lists jobs by opaque key and total,
  not decomposed tenant/identity/session** — the same one-way,
  length-prefixed key format per-job budget ceiling uses. Correlate a key
  to a specific identity via the audit log instead, where all three fields
  are already recorded per entry.

When `features.postgres_storage` is also on, the per-job cost counter is
backed by a shared Postgres table instead of an in-process map, the same
pattern [per-job budget ceiling]({{< relref "job-budget" >}}) uses for its
own Postgres option — every replica pointed at the same database enforces
the same ceiling, so it no longer scales with replica count. A
Postgres-backed check that errors or times out **fails open** (an allowed
call, marked with a `FailedOpen` audit reason), the same
availability-over-enforcement posture as budget enforcement, per-job budget
ceiling, and credential revocation.
