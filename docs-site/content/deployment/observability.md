---
title: "Observability"
weight: 40
---

## OpenTelemetry tracing

```yaml
tracing:
  otlp_endpoint: "otel-collector:4317"
  service_name: "wardline"
```

## Live dashboard

A vanilla-JS single-page dashboard showing a live, per-replica view of
recent audit entries (ring-buffer-backed, no persistence beyond the
buffer's capacity) — see the dashboard's own `GET /dashboard/api/*`
endpoints for programmatic access, including
`GET /dashboard/api/anomalies` when anomaly detection is on.
