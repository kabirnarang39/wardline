---
title: "Anomaly Detection"
weight: 50
summary: "Rule/statistics-based detection of unusual agent behavior."
---

Heuristic (not ML) detection of unusual per-identity behavior — rate
spikes, novel tool usage, and deny-rate spikes — logged for review, not
auto-blocked. Enable with:

```yaml
features:
  anomaly_detection: true
anomaly:
  output: stdout
  window_seconds: 60
  rate_spike: {enabled: true, rate_multiplier: 5, min_calls: 10}
  novel_tool: {enabled: true}
  deny_rate_spike: {enabled: true, threshold: 0.5, min_calls: 10}
```

## Known limitations

- Rule/statistics-based only — ML-based detection is an explicit v2.0
  roadmap item, not this cycle.
- Detect-and-log only, no auto-block — auto-response is a materially
  bigger trust decision (false positives cause outages, not just noisy
  logs).
- Scoped to a single identity's history on a single Wardline instance —
  no cross-identity or cross-instance correlation. Federation (v2.0
  roadmap) is the natural point to revisit this.
- Baseline state (rate/novel-tool history) resets on restart — in-memory
  only, no persistence. The failure mode is strictly more false
  positives right after a restart, never a missed detection.
- No dashboard frontend anomaly panel yet — ships a `GET
  /dashboard/api/anomalies` JSON API only.
