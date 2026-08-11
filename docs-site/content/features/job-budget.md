---
title: "Per-Job Budget Ceiling"
weight: 57
summary: "A hard cap on total calls per (tenant, identity, session), independent of the per-window rate limiter — catches a runaway job, not just a fast one."
---

[Budget enforcement]({{< relref "budget-enforcement" >}}) limits *rate* — calls
per window. It says nothing about a job that stays well under every
per-call rate limit but never stops: a retry loop that keeps calling the
same tool, slowly, forever. Per-job budget ceiling caps the *total* — calls
per job, no window to reset against.

**Credit to IronAndCoder**, who reported the incident that motivated this on
Reddit: a job estimated at pennies ballooned to roughly 20x its expected
cost. The cause was a retry loop hammering a slow tool, one call at a time
— slow enough that every per-call and per-window rate limit passed the
whole way through. Nothing was fast enough to look like abuse; it was just
relentless. Their follow-up observation is the reason this exists as its
own signal rather than a bigger `budget_enforcement` number: **every time
they hit the ceiling, the root cause was a bug, never a legitimately
expensive job.** The cap doubles as a diagnostic — if you're hitting it,
something upstream is looping, not scaling.

Enable with:

```yaml
features:
  job_budget: true
job_budget:
  requests_per_job: 500          # optional -- defaults to 500 when unset
  session_window_seconds: 300    # optional -- fallback session width when no session header is sent; defaults to 300
```

## Sessions

A "job" is the same `(tenant, identity, session)` triple [taint
tracking]({{< relref "taint-tracking" >}}) established: the explicit
`X-Wardline-Session` header when the agent framework stamps one per run, or
a per-identity sliding TTL window as a fallback when it doesn't. See [Taint
tracking → Sessions]({{< relref "taint-tracking#sessions" >}}) for the exact
mechanics — job budget uses the same fallback logic, with its own
`job_budget.session_window_seconds` (defaults to 300, independent of
`taint.session_window_seconds` — job budget works without `taint_tracking`
being on).

## Two consumption points

1. **A hard proxy gate, always on when the flag is on, zero extra config.**
   Every gated call increments the job's counter; a call that would push
   the count past `requests_per_job` gets `429` and is **not forwarded
   upstream**. The audit entry records decision `job_budget_exceeded` — a
   distinct value from `throttled` (budget enforcement's rate-limit
   decision), on purpose: the two mechanisms catch different failure
   shapes, and collapsing them into one decision would make a runaway job
   indistinguishable from an ordinary rate-limited burst in the audit
   trail. Grep for `job_budget_exceeded` and you're looking at the
   diagnostic signal IronAndCoder described, not a false-positive rate
   limit.

2. **An optional `input.job_over_budget` field in Rego**, mirroring
   `input.tainted`. A hard 429 is the simplest outcome; pairing
   `job_over_budget` with `approval` instead routes the over-budget job
   through [approval workflow]({{< relref "approval-workflow" >}}) — an
   operator sees it and decides whether to let it continue, rather than a
   flat block:

   ```rego
   package wardline.authz

   default allow = false

   approval {
     input.job_over_budget
   }

   allow {
     input.identity == "agent-abc123"
   }
   ```

   See the [Rego reference]({{< relref "policy-rego-reference" >}}) for the
   full result contract. `input.job_over_budget` is read-only from a
   policy's perspective: consulting it never increments the job's count —
   only the hard gate above does that, exactly once per request, so a
   policy that checks the field on every evaluation can't itself trip the
   ceiling.

## Boundary — what this is and isn't

- **Request-count only, in this version — not token or dollar cost.** The
  ceiling counts calls, not what they cost. A `Meter` implementation keyed
  on tokens or spend is a plausible future adapter behind the same
  interface (see [Budget enforcement]({{< relref "budget-enforcement" >}})'s
  own known limitation on this), but it isn't shipped — don't read
  `requests_per_job` as a cost cap.
- **No cross-job or cross-identity aggregation.** The ceiling is scoped to
  one job — one `(tenant, identity, session)`. Ten sessions each at 499
  calls is nowhere near any limit this feature enforces; it isn't a
  fleet-wide or per-identity total.
- **No manual reset.** There's no reset endpoint or admin action that
  clears a job's count mid-session. The ceiling holds until the session
  itself rotates — the header value changes, or (in fallback mode) the TTL
  window lapses — the same boundary that ends taint's session.
- **The dashboard's job-budget view lists jobs by opaque key and count,
  not decomposed tenant/identity/session.** The key is a length-prefixed
  composition of the three (the same anti-spoofing encoding used
  elsewhere in this codebase, e.g. credential revocation's key format) —
  one-way by design, so the dashboard can show "this job is at 480/500"
  without being able to reverse the key back into its parts. Correlate a
  key to a specific identity via the audit log instead, where all three
  fields are already recorded per entry.

When `features.postgres_storage` is also on, the per-job counter is backed
by a shared Postgres table instead of an in-process map, the same pattern
[Budget enforcement]({{< relref "budget-enforcement" >}}) uses for its own
Postgres option — every replica pointed at the same database enforces the
same ceiling, so it no longer scales with replica count. A Postgres-backed
check that errors or times out **fails open** (an allowed call, marked with
a `FailedOpen` audit reason), the same availability-over-enforcement
posture as budget enforcement and credential revocation.
