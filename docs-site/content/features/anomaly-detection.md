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

Every identity's baseline state is garbage-collected on
`anomaly.gc_interval_seconds` (an entry idle for more than 2x that
interval is dropped, reappearing as "novel" on its next call — the same
conservative posture as a restart). `gc_interval_seconds` is a
three-way-coupled knob once `postgres_storage` is also on: it
simultaneously sets (a) this eviction cutoff (2x interval), (b) the
ceiling `auto_block.block_duration_seconds` may validate against (must
stay `<= 2x gc_interval_seconds`, so a block always expires before its
identity can go stale enough to be evicted), and (c) checkpoint
frequency (below). Lowering it to shrink the crash-loss window also
makes eviction more aggressive and may force `block_duration_seconds`
shorter too — tune with all three effects in mind, not just whichever
one motivated the change.

When `features.postgres_storage` is also on, that same GC tick doubles
as a checkpoint: the full set of per-identity baselines still in memory
is upserted into a shared Postgres table (in batches, each its own
transaction, so an arbitrarily large identity population doesn't risk
one all-or-nothing transaction timing out) and reloaded once at
startup — so a restart no longer wipes every identity's history at
once. The same GC pass also deletes the Postgres row for every identity
just evicted from memory, so an evicted identity doesn't resurrect a
stale baseline from a leftover row on the next restart. Because the save
only happens on the GC tick, not on every call or on shutdown, a
baseline can be up to one `gc_interval_seconds` stale relative to the
most recent traffic, whether the process ends in a crash or a graceful
stop. This is single-instance persistence, not cross-instance sharing —
every row is keyed on `(instance_id, tenant, identity)`, not just
`(tenant, identity)`, where `instance_id` defaults to this replica's own
hostname (the same derivation federation's own instance ID uses), so
each replica still checkpoints and reloads only the traffic it itself
has seen even when every replica shares one Postgres database (see
"Known limitations" below for what that does and doesn't cover).

When `features.web_ui` is also on, the dashboard's **Anomalies** panel
gives this feature's `GET /dashboard/api/anomalies` a live view in the
UI — see [Observability](/deployment/observability/)'s "Live dashboard"
section.

## Known limitations

- Scoped to a single identity's history on a single Wardline instance —
  no cross-identity or cross-instance correlation. Federation has
  already shipped (see [Roadmap](/advanced/roadmap/)'s "v2.0 (shipped)"
  section; it has no dedicated docs page yet), but it doesn't close
  this gap: it correlates *alerts* — a
  fingerprint-count threshold across instances — not raw per-identity
  call history, so a correlated alert across instances never shares or
  merges the underlying baseline state itself.
- Baseline state (rate/novel-tool/`ml_score` history) resets on
  restart, in-memory only — UNLESS `features.postgres_storage` is also
  on: baselines then persist to a shared Postgres table and reload at
  startup, checkpointed on the same interval as GC
  (`anomaly.gc_interval_seconds`), the same way credential revocation
  and refresh tokens already do for their own state. See [HA
  deployment](/features/ha-deployment/) and [Credential
  issuance](/features/credential-issuance/)'s sibling Postgres-backed
  features for the general pattern. Persistence is still per-instance,
  not per-fleet: it does not share baselines across replicas (each
  replica keeps learning only from the traffic it itself sees, enforced
  by keying every row on `(instance_id, tenant, identity)` — see HA
  deployment's per-replica limitations), and there's no schema-migration
  mechanism for the persisted JSON shape if it ever needs to change.
  `instance_id` defaults to the replica's own hostname, so a hostname
  change (pod recreation on a rolling deploy) orphans that replica's old
  rows under the previous hostname — never reloaded again, harmless
  (same "reappears as novel" fallback as any other eviction) but not
  currently pruned either; see the next bullet.
- Rows for an instance ID that never restarts again (a replica
  permanently scaled down, or one whose hostname changed) are not
  pruned — only rows belonging to identities evicted by a still-running
  instance's own GC pass are deleted. Cleaning up a fully-abandoned
  instance ID's rows is a coarser, lower-priority problem left for a
  future cycle.
- Currently-blocked identities are surfaced both as the `GET
  /dashboard/api/anomalies/blocked` JSON API and, when `web_ui` is on, a
  dedicated **Blocked** panel in the dashboard. A block can be cleared
  early via `DELETE /dashboard/api/anomalies/blocked/{identity}`, gated
  by the same `credential:revoke` permission as credential revocation
  (when `rbac` is on) — otherwise it simply expires once its TTL elapses.
  This is a shipped capability, listed here only to note the one residual
  gap: the block store is per-replica unless `postgres_storage` is also
  on (see [HA deployment](/features/ha-deployment/)).
