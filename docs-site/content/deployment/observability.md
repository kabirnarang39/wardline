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
