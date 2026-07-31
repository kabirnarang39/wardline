---
title: "Anomaly Detection"
weight: 50
summary: "Rule/statistics and ML-based detection of unusual agent behavior, with optional auto-block."
---

Rule/statistics detection of unusual per-identity behavior — rate
spikes, novel tool usage, and deny-rate spikes — plus a fourth,
independently-toggleable `ml_score` heuristic: a combined z-score over
four per-identity, per-window features (call rate, distinct-tool count,
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
  ml_score: {enabled: true, score_threshold: 3.0, min_calls: 5}
  auto_block: {enabled: true, score_threshold: 8.0, block_duration_seconds: 300}
```

`ml_score.score_threshold` must be less than or equal to
`auto_block.score_threshold` (config validation enforces this) — an
operator can log at a lower sensitivity than they block at, never the
reverse. `ml_score` needs at least 8 completed windows of history per
identity before it can score anything at all: a 2- or 3-sample stddev is
statistical noise, not signal, and treating it as signal is exactly what
caused ordinary traffic to auto-block early on.

`ml_score.min_calls` is the matching floor on the window being scored,
rather than on the history behind it: a window with fewer calls than this
is neither scored nor folded into any baseline. A near-empty window drives
a feature to a range extreme for reasons unrelated to behavior — a single
call has no inter-arrival gap at all, so that feature reads as maximally
bursty — so scoring such a window is how an identity that simply went
quiet ends up blocked. `min_calls` must be at least 2; config validation
rejects 1.

## Known limitations

- Scoped to a single identity's history on a single Wardline instance —
  no cross-identity or cross-instance correlation. Federation shipped in
  v2.0#1 (see [Roadmap](/advanced/roadmap/); it has no dedicated docs
  page yet), but it doesn't close this gap: it correlates *alerts* — a
  fingerprint-count threshold across instances — not raw per-identity
  call history, so a correlated alert across instances never shares or
  merges the underlying baseline state itself.
- Baseline state (rate/novel-tool/`ml_score` history) resets on restart —
  in-memory only, no persistence. The failure mode is strictly more false
  positives right after a restart, never a missed detection.
- No dashboard frontend anomaly panel yet — ships `GET
  /dashboard/api/anomalies` and `GET /dashboard/api/anomalies/blocked`
  JSON APIs only. `auto_block` can be cleared early via `DELETE
  /dashboard/api/anomalies/blocked/{identity}`, gated by the same
  `credential:revoke` permission as credential revocation (when `rbac`
  is on) — otherwise it simply expires once its TTL elapses.
