---
title: "Benchmarks"
weight: 30
summary: "Real load-test numbers for the proxy, budget, credential issuance, and gRPC transport hot paths -- and the one real bottleneck they found."
---

Real, sustained, concurrent load through a real `wardline serve` process --
not synthetic numbers. The suite lives at `bench/` and reproduces with:

```bash
go install github.com/tsenart/vegeta@latest   # HTTP load generator
./bench/run.sh
```

It drives [vegeta](https://github.com/tsenart/vegeta) against the HTTP
proxy path and a purpose-built raw-gRPC load client
(`bench/grpcload`) against the [gRPC transport](/features/grpc-transport/),
covering the v0.1 baseline hot path, the same path with every optional
feature also on, credential issuance, and budget enforcement actually
holding its line under overload.

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

## Results

| Scenario | Rate | Success | p50 | p95 | p99 |
|---|---|---|---|---|---|
| Baseline allow (proxy + policy + audit) | 500 req/s | 100% | 0.43ms | 1.48ms | 13.6ms |
| Baseline deny | 500 req/s | 100% (all correctly 403) | 0.28ms | 0.74ms | 1.79ms |
| **Baseline allow, unbounded** | max (300 workers) | **100%, 0 errors** | 8.9ms | 48.8ms | 111ms |
| Full stack: credential issuance (`POST /credentials/token`) | 500 req/s | 100% | 1.52ms | 1.76ms | 2.30ms |
| Full stack allow (Bearer token; budget + anomaly + credential + audit all on) | 500 req/s | 100% | 0.82ms | 2.22ms | 10.4ms |
| gRPC transport passthrough (Bearer token) | max (50 workers) | 100%, 0 errors | 1.28ms | 2.44ms | 3.35ms — **35,895 req/s throughput** |
| Budget enforcement under 5x overload (100 req/window/1s) | 500 req/s | exactly 20% (1,500 allowed / 6,000 denied) | — | — | — |
| Budget tenant-override AND-semantics (global default huge, tenant override 100/window/1s) | 500 req/s | exactly 20% (1,500 allowed / 6,000 denied) | 0.23ms | 0.60ms | 1.26ms |
| oidc bootstrap (`POST /credentials/token`, real JWKS verify) | 500 req/s | 100% | 1.12ms | 1.49ms | 2.84ms |
| oidc allow path (bootstrapped bearer token) | 500 req/s | 100% | 0.32ms | 0.50ms | 0.92ms |
| mtls bootstrap (`POST /credentials/token`, header-based) | 500 req/s | 100% | 1.03ms | 1.17ms | 1.27ms |
| mtls allow path (bootstrapped bearer token) | 500 req/s | 100% | 0.39ms | 1.15ms | 2.63ms |

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

## A real bottleneck this benchmark found and fixed

The unbounded max-throughput run originally sustained only **~4,100
req/s**, with p99 climbing past 200ms even though the mock upstream
alone (tested in isolation, no Wardline in front) handles ~89,000
req/s. That gap meant the bottleneck was Wardline's own request path,
not the upstream or the load generator.

The cause: `http.Transport`'s default `MaxIdleConnsPerHost` is **2**.
Wardline's entire job is fronting a small number of upstream hosts
(often exactly one) under concurrent load from many agents at once —
that default limits connection *reuse* to 2 pooled connections per
host, so any concurrency past trivial forces a fresh TCP dial and
handshake per request instead of reusing a keep-alive connection. Fine
at low concurrency, a real ceiling under load.

The fix (`internal/features/proxy/adapter/handler.go`,
`upstreamMaxIdleConnsPerHost`): raise it to 256. Unbounded throughput on
the same machine, same config, same mock upstream went from ~4,100 to
**~20,900 req/s — about 5x — with p99 falling from 200ms+ to 111ms and
0 errors** at every concurrency level tested. `TestNewHandler_TunesMaxIdleConnsPerHost`
(`internal/features/proxy/adapter/handler_transport_test.go`) pins
this so it can't silently regress back to the default.

This is the standard, well-documented fix for exactly this class of Go
reverse-proxy bottleneck — not a workaround, the actual industry-standard
tuning every Go HTTP proxy in production applies for the same reason.

## Reproducing

```bash
./bench/run.sh
# or tune the load:
BENCH_RATE=2000 BENCH_DURATION=30s BENCH_MAX_WORKERS=500 ./bench/run.sh
```

Raw vegeta reports (`.bin`/`.txt`) and per-scenario server/audit/anomaly
logs land under `bench/.out/`.
