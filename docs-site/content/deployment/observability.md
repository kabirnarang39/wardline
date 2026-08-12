---
title: "Observability"
weight: 40
---

## OpenTelemetry tracing

Off by default. Requires `features.otel_tracing: true` — without it,
`tracing:` is parsed but ignored and no spans are exported:

```yaml
features:
  otel_tracing: true
tracing:
  otlp_endpoint: "otel-collector:4317"
  service_name: "wardline"
```

## Prometheus metrics

Off by default. Requires `features.prometheus_metrics: true` — without it,
`GET /metrics` is a plain 404, same shadowing behavior as every other
flag-gated route (`/scim/v2/*`, `/federation/summaries`, ...):

```yaml
features:
  prometheus_metrics: true
```

Exposes the standard Prometheus text exposition format at `GET /metrics`:

- `wardline_proxy_requests_total{decision}` — a counter, one series per
  proxy decision (`allow`, `deny`, `throttled`, `passthrough`, `error`,
  `blocked`, `needs_approval`, `job_budget_exceeded`,
  `cost_budget_exceeded`).
- `wardline_proxy_request_duration_seconds{decision}` — a histogram of the
  same requests' latency, using Prometheus's own default buckets.
- The standard Go runtime and process collectors (`go_goroutines`,
  `go_memstats_*`, `process_resident_memory_bytes`, ...) — the same
  goroutine/heap-growth signals the [runbook](/deployment/runbook/)'s
  soak-test guidance describes watching via pprof, now scrapeable directly
  instead of requiring a debugger attached to the process.

Deliberately **not** labeled by tool name: unlike `decision` (a closed set
of literals this codebase itself produces), the tool a caller requests is
attacker-controlled input — see anomaly detection's own novel-tool-burst
attack pattern — and using it as a label would let any caller grow this
process's metric cardinality without bound simply by sending distinct tool
names.

## Live dashboard

Off by default. Requires `features.web_ui: true` — without it, the
dashboard routes aren't mounted at all:

```yaml
features:
  web_ui: true
```

A vanilla-JS single-page dashboard showing a live, per-replica view of
recent audit entries (ring-buffer-backed, no persistence beyond the
buffer's capacity) — see the dashboard's own `GET /dashboard/api/*`
endpoints for programmatic access, including
`GET /dashboard/api/anomalies` when anomaly detection is on.
