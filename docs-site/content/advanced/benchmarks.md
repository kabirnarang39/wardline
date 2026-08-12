---
title: "Benchmarks"
weight: 30
summary: "Real load-test numbers for every feature, plus cross-cutting risk-combo, HA, and soak runs."
---

Real, sustained, concurrent load through a real `wardline serve` process --
not synthetic numbers. The suite lives at `bench/` and reproduces with:

```bash
go install github.com/tsenart/vegeta@latest   # HTTP load generator
./bench/run.sh
```

It drives [vegeta](https://github.com/tsenart/vegeta) and a handful of
purpose-built load clients (`bench/grpcload`, `bench/anomalyattack`,
`bench/sessionload`, `bench/scimload`, `bench/federationwait`, ...) against
every feature this proxy ships, plus three cross-cutting runs: 3-5
risk-based feature-flag combinations, an HA run (2 replicas sharing one
Postgres pool), and a 30-60 minute soak.

## Machine and method

Numbers below are from one run on a 10-core Apple M4 laptop, not a
production cluster -- read them as *relative* (what costs what, whether a
limiter actually holds) and as proof the methodology is real, not as an
SLA promise for your hardware. Run `./bench/run.sh` on your own target
machine for numbers that mean something for your deployment.

Two mock upstreams stand in for a real MCP server so the numbers measure
Wardline's own overhead, not a stand-in's: `bench/httpupstream` for HTTP
(a concurrent Go server -- alone it sustains ~89,000 req/s at ~1.4ms
p50, confirmed by benchmarking it directly with nothing in front of it)
and `bench/grpcload upstream` for gRPC.

**Finding this machine's real ceiling**: sweeping sustained rate (not
raw connection count) against the baseline allow path with a fixed,
keep-alive-reusing worker pool, throughput peaks around **~37,000-
38,800 req/s** (p50 2-4ms, p99 9-12ms, 100% success, 0 errors) at
100-150 concurrent connections, then degrades past ~300-500 as the
load generator and Wardline compete for the same 10 CPU cores on one
machine -- a same-host testing artifact (both processes fighting for
cores), not a Wardline-side defect: success stays 100% the whole way,
it's purely a latency/throughput curve, never an error rate. Past
~500-800 concurrent *new* connections specifically (not the sustained-
rate sweep above), the load generator itself hits macOS's default
listen backlog (`kern.ipc.somaxconn=128`) and ephemeral port range
before Wardline's own capacity does -- a genuine ceiling for
same-host loopback testing, not for Wardline running on a real host
under real distributed client load with persistent connections.

## Results

| Scenario | Rate | Success | p50 | p95 | p99 |
|---|---|---|---|---|---|
| Baseline allow (proxy + policy + audit) | 500 req/s | 100% | 0.43ms | 1.48ms | 13.6ms |
| Baseline deny | 500 req/s | 100% (all correctly 403) | 0.28ms | 0.74ms | 1.79ms |
| **Baseline allow, unbounded** | max (300 workers) | **100%, 0 errors** | 8.9ms | 48.8ms | 111ms |
| **Baseline allow, real ceiling** (sustained-rate sweep, 100-150 reused connections) | up to 100,000 req/s target | **100%, 0 errors** — sustains ~37,000-38,800 req/s | 2.1ms | 6.0ms | 9.0ms |
| Full stack: credential issuance (`POST /credentials/token`) | 500 req/s | 100% | 1.52ms | 1.76ms | 2.30ms |
| Full stack allow (Bearer token; budget + anomaly + credential + audit all on) | 500 req/s | 100% | 0.82ms | 2.22ms | 10.4ms |
| gRPC transport passthrough (Bearer token) | max (50 workers) | 100%, 0 errors | 1.28ms | 2.44ms | 3.35ms — **35,895 req/s throughput** |
| Budget enforcement under 5x overload (100 req/window/1s) | 500 req/s | exactly 20% (1,500 allowed / 6,000 denied) | — | — | — |
| Budget tenant-override AND-semantics (global default huge, tenant override 100/window/1s) | 500 req/s | exactly 20% (1,500 allowed / 6,000 denied) | 0.23ms | 0.60ms | 1.26ms |
| oidc bootstrap (`POST /credentials/token`, real JWKS verify) | 500 req/s | 100% | 1.12ms | 1.49ms | 2.84ms |
| oidc allow path (bootstrapped bearer token) | 500 req/s | 100% | 0.32ms | 0.50ms | 0.92ms |
| mtls bootstrap (`POST /credentials/token`, header-based) | 500 req/s | 100% | 1.03ms | 1.17ms | 1.27ms |
| mtls allow path (bootstrapped bearer token) | 500 req/s | 100% | 0.39ms | 1.15ms | 2.63ms |
| RBAC dashboard, viewer-bound identity | 500 req/s | 100% allowed | 0.15ms | 0.41ms | 0.99ms |
| RBAC dashboard, unbound identity | 500 req/s | 100% correctly denied (403) | 0.16ms | 0.33ms | 0.60ms |
| Anomaly detection: attack-shaped burst (novel-tool + deny-rate spike) | max (50 workers) | **auto_block fired** — ~50,000 req/s sustained during the burst | 1.0ms | 2.5ms | 4.0ms |
| gRPC transport, TLS on (spiffe_workload_identity + real mutual TLS to upstream) | max (50 workers) | 100%, 0 errors | 0.91ms | 1.61ms | 2.09ms — **51,520 req/s throughput** |
| SCIM filter query (`GET /scim/v2/Users?filter=...`) | 500 req/s | 100% | 0.27ms | 0.45ms | 0.88ms |
| **SCIM Bulk create (5 ops/request)** | max (50 workers) | **100%, 0 errors** | 0.69ms | 3.15ms | 5.01ms — **49,689 bulk-req/s (248,445 Create ops/s)** |
| Dashboard: 4 concurrent API endpoints + live proxy traffic | 100 req/s each endpoint, 500 req/s proxy | 100% (all 5 concurrent streams) | 0.35–0.65ms | 0.6–1.2ms | 1.1–2.2ms |
| Postgres storage: audit + budget + anomaly on one shared pool (5 identities) | 100 req/s per identity | 100% | 1.2–1.4ms | 1.9–2.5ms | 3.5–4.1ms |
| Federation: 2 instances, real signed publish + correlate under load | 100 req/s each instance | 100% (both instances); correlated on both sides | 1.0ms | 1.7ms | 2.6ms |
| Job budget ceiling (100/job) under 5x overload | 500 req/s | exactly 1.33% (100 allowed / 7,400 denied) | — | — | — |
| Job cost budget ceiling (1000/10-per-call) under 5x overload | 500 req/s | exactly 1.33% (100 allowed / 7,400 denied) | — | — | — |
| Taint tracking: 30 concurrent sessions, per-session isolation | 30 concurrent sessions × 20 cycles | 100% correct (0 cross-session leakage) | — | — | — |
| Approval workflow: 20 concurrent sessions, own pending/grant | 20 concurrent sessions × 10 cycles | 100% correct (0 cross-session leakage) | — | — | — |
| OTel tracing: baseline allow path with span export on | 500 req/s | 100% | 0.57ms | 1.16ms | 2.30ms |
| Risk combo: rbac + scim + web_ui + postgres_storage (SCIM-derived binding + shared pool) | 500 req/s proxy, 100 req/s dashboard | 100% (proxy + viewer), 100% correctly denied (unbound) | 1.2ms | 2.4ms | 4.5ms |
| Risk combo: taint + approval + job_budget + job_cost_budget (all four session-keyed) | 20 concurrent sessions × 10 cycles | 100% correct, no cross-feature interference | — | — | — |
| **HA: 2 replicas, shared Postgres budget + audit, same load** | 500 req/s per replica (1,000 req/s combined) | **exactly 1,000/15,000 admitted** (matches the shared ceiling precisely — no double-counting) | 1.3ms | 3.0ms | 60ms |
| **Soak: 30 min sustained, real wall-clock time** | 150 req/s (270,000 requests total) | **100%, 0 errors** | 0.81ms | 1.46ms | 2.19ms |

Two things worth calling out on their own:

- **The full feature stack (budget, anomaly detection, credential
  issuance, audit, all on at once) costs single-digit milliseconds of
  p99 over the v0.1 baseline** — the whole point of the layered
  architecture (identity → auto-block → policy → budget → audit) is
  that each stage is a cheap in-memory check, and the numbers bear that
  out.
- **Budget enforcement holds its line exactly, not approximately**: a
  100-req/second-window limit under 5x sustained overload for 15
  seconds admitted precisely 1,500 requests and rejected the other
  6,000 with `429`, not a fail-open gap under load — see [Budget
  Enforcement](/features/budget-enforcement/).

## Reproducing

```bash
./bench/run.sh
# or tune the load:
BENCH_RATE=2000 BENCH_DURATION=30s BENCH_MAX_WORKERS=500 ./bench/run.sh
```

Raw vegeta reports (`.bin`/`.txt`) and per-scenario server/audit/anomaly
logs land under `bench/.out/`.

The soak test (30-60 real minutes, watching for memory/goroutine
growth) is a separate script, deliberately not part of `run.sh`'s own
fast (~5 minute) suite:

```bash
./bench/soak.sh
# or run the full hour:
SOAK_DURATION_SECONDS=3600 ./bench/soak.sh
```
