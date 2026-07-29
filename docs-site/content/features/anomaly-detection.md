---
title: "Anomaly Detection"
weight: 50
summary: "Rule/statistics and ML-based detection of unusual agent behavior, with optional auto-block."
---

Rule/statistics detection of unusual per-identity behavior — rate
spikes, novel tool usage, and deny-rate spikes — plus a fourth,
independently-toggleable `ml_score` heuristic: a combined z-score over
four per-identity, per-window features (call rate, tool-diversity ratio,
deny ratio, mean inter-arrival time), each scored against its own
running mean/variance baseline (Welford's algorithm — no stored history,
no training data). All four are logged for review by default; `ml_score`
can additionally drive `auto_block`, which rejects every one of an
identity's calls for a configured duration once its score clears a
separate, stricter threshold. Enable with:

```yaml
features:
  anomaly_detection: true
anomaly:
  output: stdout
  window_seconds: 60
  rate_spike: {enabled: true, rate_multiplier: 5, min_calls: 10}
  novel_tool: {enabled: true}
  deny_rate_spike: {enabled: true, threshold: 0.5, min_calls: 10}
  ml_score: {enabled: true, score_threshold: 3.0}
  auto_block: {enabled: true, score_threshold: 8.0, block_duration_seconds: 300}
```

`ml_score.score_threshold` must be lower than `auto_block.score_threshold`
(config validation enforces this) — an operator can log at a lower
sensitivity than they block at, never the reverse. `ml_score` needs at
least 8 completed windows of history per identity before it can score
anything at all: a 2- or 3-sample stddev is statistical noise, not
signal, and treating it as signal is exactly what caused ordinary
traffic to auto-block early on.

## Known limitations

- Scoped to a single identity's history on a single Wardline instance —
  no cross-identity or cross-instance correlation. Federation (v2.0
  roadmap) is the natural point to revisit this.
- Baseline state (rate/novel-tool/`ml_score` history) resets on restart —
  in-memory only, no persistence. The failure mode is strictly more false
  positives right after a restart, never a missed detection.
- `auto_block` is strictly time-bounded with no manual early unblock this
  cycle — the block simply expires once its TTL elapses.
- No dashboard frontend anomaly panel yet — ships `GET
  /dashboard/api/anomalies` and `GET /dashboard/api/anomalies/blocked`
  JSON APIs only.
