---
title: "On-Call Runbook"
weight: 50
---

What to check when Wardline is paging you, in order. This complements
[High Availability](/deployment/high-availability/) and
[Observability](/deployment/observability/) (how to configure) with
what to actually *do* when something's wrong — failure-mode behavior
confirmed by real chaos testing (killing Postgres, killing a replica,
and killing a federation peer mid-load), not guesswork.

## First: is it actually down, or just degraded?

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://<replica>/healthz   # liveness -- always 200 once started
curl -s -o /dev/null -w '%{http_code}\n' http://<replica>/readyz    # readiness -- 503 during shutdown, or if postgres_storage is on and Postgres is unreachable
```

`/healthz` returning anything but 200 means the process itself is
wedged or dead — restart it. `/readyz` returning 503 while `/healthz`
is 200 means the process is alive but has a real dependency problem
(see "Postgres is unreachable" below) or is mid-graceful-shutdown —
check the log for `"shutting down"` before assuming the latter.

## Log-line signatures and what they actually mean

Confirmed against the real binary, not inferred from source alone:

| Log line (level) | Meaning | Action |
|---|---|---|
| `"budget check failed open: treating as within budget"` (WARN) | Postgres-backed budget check couldn't reach the DB for that request; the request was **admitted anyway** (availability over enforcement — confirmed by chaos testing, this is not a crash or a hang). | Check Postgres reachability. Enforcement is silently absent until it's restored — not an emergency by itself, but don't ignore a sustained stream of these. |
| `"audit write failed"` (ERROR) | Same Postgres outage; that request's audit entry is **lost, not queued or retried** (confirmed by chaos testing). | Same as above. If this needs to be a compliance gap you can't accept, that's a capacity-planning/Postgres-HA conversation, not a Wardline bug — see [Postgres storage](/features/postgres-storage/) (or the shared-pool section of the docs covering it). |
| `"federation publish failed"` (ERROR) | This instance's anomaly summary for that publish tick couldn't reach one peer. **Not retried** for that specific tick (confirmed by chaos testing) — the local proxy hot path and this instance's own detection are unaffected. | Check the named peer's reachability. A subsequent anomaly on either side correlates normally once both instances are healthy again — no action needed beyond fixing peer connectivity. |
| `"insecure default: identity is trusted from the X-Wardline-Identity header..."` (WARN) | Expected, not a problem, unless you intended `credential_issuance` to be on. | If you expected verified identity, check `features.credential_issuance`. |
| `"anomaly baselines are in-process only..."` / `"budget enforcement is in-process only..."` / `"scim-provisioned bindings are in-process only..."` (WARN) | Expected on every replica unless `features.postgres_storage` is also on. Each replica has its own independent view of that state. | If you're running >1 replica and need shared state (budget ceilings that mean the fleet total, not N× the configured number; anomaly detection seeing the whole fleet's traffic; SCIM bindings surviving a restart), turn on `postgres_storage`. |
| `"debug pprof endpoint enabled..."` (WARN) | `WARDLINE_DEBUG_PPROF` is set. Unauthenticated, loopback-only. | Should not be set in production. If you see this and didn't set it intentionally for live debugging, find out who did and why. |

## Postgres is unreachable

Confirmed behavior end to end (killed the container mid-load, watched
recovery): the process **does not crash**. Budget checks fail open
(requests admitted, not enforced). Audit writes fail loudly and that
window's entries are lost, not queued. Once Postgres is reachable
again, **no restart is needed** — the shared pool reconnects on its
own and behavior returns to normal automatically, typically within a
few seconds of Postgres accepting connections again.

Action: fix Postgres. There is no Wardline-side lever to pull here
beyond that — this is the documented availability-over-durability
tradeoff (see [Budget Enforcement](/features/budget-enforcement/)'s
own coverage of the shared Postgres pool, and
`internal/platform/pgpool`'s doc comment), not a bug to patch around.

## One replica died

Confirmed behavior (violently killed a replica — `SIGKILL`, no
graceful shutdown — mid-load, load continued against the survivor):
the other replica(s) are **completely unaffected** — no shared-lock
contention, no crash propagation, no double-counting or gap in the
shared Postgres-backed budget/audit state once the dead replica's
in-flight requests finish erroring out client-side. A load balancer
health-checking `/healthz` will route around it once it stops
responding.

Action: standard "why did the process die" investigation (OOM kill,
node eviction, `kubectl get events`) — the *cluster's* behavior around
the death is already correct; there is nothing Wardline-specific to
fix reactively.

## A federation peer is unreachable

Confirmed behavior: the local instance's own proxy hot path and
anomaly detection are entirely unaffected. That specific peer stops
receiving this instance's anomaly summaries (logged loudly per tick,
see the log-line table above) until it's reachable again — and **that
gap is not backfilled**: a tick's data that failed to send is not
resent once the peer recovers. Once both sides are healthy, the next
anomaly on either side correlates normally.

Action: fix the peer's reachability (network, DNS, the peer process
itself). If you need the missed correlation for compliance/forensics,
it's genuinely gone for that specific window — this is a documented
limitation (see [Federation](/features/federation/)), not something to
retry after the fact.

## Latency degraded, but success rate is still 100%

Confirmed via load testing on a real machine (see
[Benchmarks](/advanced/benchmarks/)): under real overload, Wardline
degrades gracefully — throughput plateaus and latency climbs, but it
does not start erroring out. If you're seeing 100% success with
climbing p99, you are past the machine's (or container's CPU
limit's) real sustained-throughput ceiling, not looking at a bug.

Action: this is a capacity question — check CPU usage against the
container's CPU limit/request first (a proxy sharing a core with a
noisy neighbor looks exactly like this), then scale replicas
horizontally (each replica's own request-handling capacity is
independent; only Postgres-backed state is shared) rather than
searching for a code-level fix.

## Escalate immediately vs. let it self-heal

**Self-heals, don't page a human at 3am for it alone:**
- A burst of `"budget check failed open"` / `"audit write failed"`
  lines that stops once Postgres recovers.
- A burst of `"federation publish failed"` for one peer that stops
  once that peer recovers.
- Climbing latency under a real traffic spike that returns to normal
  once the spike passes.

**Escalate:**
- `/healthz` failing (the process itself is wedged/dead).
- Postgres unreachable for longer than your compliance/enforcement
  tolerance allows (budget silently unenforced, audit silently
  incomplete, for real — not a Wardline-side timer to tune, a Postgres
  availability problem).
- Any log line NOT in the table above at ERROR level, repeating.
