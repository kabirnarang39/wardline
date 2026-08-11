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

## Recall benchmark

The false-positive claim above is regression-guarded by
`TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic`. The numbers
below go further: real recall, per attack shape and severity, against
the *shipped example config* from this page (`ml_score` threshold 3.0,
`auto_block` threshold 8.0), measured against the actual `Detector` and
`BlockChecker` code — not a mockup. Reproduce with:

```bash
go test ./internal/features/anomaly/usecase/ -run TestRecallBenchmark -v
```

Every scenario warms a fresh identity for 20 windows (~30 calls/window,
±20% jitter) before the attack traffic, then reads real block/anomaly
state off the real detector. Source: `recall_benchmark_test.go`.

**Abrupt spike** — single-window spike at N× a ~30 calls/window baseline, 20 independent trials per multiple:

| Spike | Recall |
|---|---|
| 1.5× | 0% |
| 2× | 0% |
| 3× | 100% |
| 5× | 100% |
| 10× | 100% |
| 20× | 100% |

Detection is a step function, not graduated: nothing below 3× the
identity's own baseline blocks, and everything at or above it does, for
this config. An attacker who knows (or guesses) that shape can stay just
under 3× and never trip `auto_block` on a single spike — the mechanism
this "Known limitations" section's next entry describes.

**Low-and-slow** — ramp rate = +N calls/window from the same baseline, up to a 150-window ceiling:

| Ramp | Result |
|---|---|
| +1/window | never blocked (150 windows, reached 6.0× baseline) |
| +2/window | never blocked (150 windows, reached 11.0× baseline) |
| +3/window | never blocked (150 windows, reached 16.0× baseline) |
| +5/window | blocked at window 9 (2.7× baseline) |
| +10/window | blocked at window 4 (2.7× baseline) |

The blind spot has a real, measured edge, not just a qualitative
"exists": a ramp of +3 calls/window or slower evaded detection entirely
through 150 windows and 16× the original call rate in this run. A ramp
of +5/window or faster is, in practice, closer to an abrupt spike than a
patient evasion — it gets caught almost as fast as one.

**Deny-rate spike** — single-window deny ratio, 20 trials per rate. `deny_rate_spike` (always logs, never blocks on its own) vs. `ml_score`/`auto_block`:

| Deny ratio | Flagged | Auto-blocked |
|---|---|---|
| 20% | 20/20 | 0/20 |
| 40% | 20/20 | 12/20 |
| 60% | 20/20 | 11/20 |
| 80% | 20/20 | 8/20 |
| 100% | 20/20 | 13/20 |

`deny_rate_spike` fires reliably at every tested ratio, matching its
design (no window-completion gate). Auto-block recall is real but
noisier and non-monotonic across ratios — it depends on `ml_score`'s
deny-ratio feature and its own volume-decline gate, not the raw ratio
alone, so a spike gets logged well before (and independently of)
whether it also crosses the stricter block threshold.

**Novel-tool enumeration** — single-window burst of brand-new distinct tools, 20 trials per size:

| Burst | Recall |
|---|---|
| 2 | 0% |
| 5 | 0% |
| 10 | 0% |
| 20 | 0% |
| 40 | 100% |

**False-positive rate** — 20 independent identities/seeds, 300 windows each (6,000 windows total) of steady ~30 calls/window traffic with ±20% jitter, post-warmup: **0/6,000 flagged (0.00%)**, matching the single-seed regression test above at 20× the sample size.

This is one synthetic corpus against the shipped example config, not an
independent red-team evaluation — see "Known limitations" below for what
it doesn't cover (most importantly, low-and-slow, which this benchmark
quantifies rather than closes).

## Known limitations

- **Low-and-slow evasion.** Because the baseline is self-learned per
  identity (Welford, unsupervised), an attacker who ramps activity
  gradually — staying within a few standard deviations of the moving
  baseline each window — is never auto-blocked: the baseline adapts
  upward and absorbs the ramp. Wardline blocks *abrupt* deviations, not
  *patient* ones. This is an inherent tradeoff of unsupervised baselining,
  not a tunable threshold (tightening it would raise the false-positive
  rate the detector is regression-guarded to keep near zero). Both the
  abrupt-spike block and the low-and-slow evasion are pinned by tests
  (`TestDetector_AutoBlock_AbruptSpikeIsBlocked` and
  `TestDetector_AutoBlock_LowAndSlowEvades`). Pair anomaly detection with
  explicit policy and budget limits, which bound absolute behavior
  regardless of ramp speed.
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
  (same "reappears as novel" fallback as any other eviction). Such
  orphaned rows, and those of any permanently scaled-down replica, are
  cleaned up automatically: every live replica's GC tick prunes baseline
  rows not re-checkpointed in the last few GC intervals (any instance's,
  not just its own). Because a live replica re-upserts all of its own
  rows every tick, only rows belonging to an instance that has stopped
  checkpointing entirely ever fall past that cutoff. The one residual
  limitation is that there's no schema-migration mechanism for the
  persisted JSON shape if it ever needs to change.
- Currently-blocked identities are surfaced both as the `GET
  /dashboard/api/anomalies/blocked` JSON API and, when `web_ui` is on, a
  dedicated **Blocked** panel in the dashboard. A block can be cleared
  early via `DELETE /dashboard/api/anomalies/blocked/{identity}`, gated
  by the same `credential:revoke` permission as credential revocation
  (when `rbac` is on) — otherwise it simply expires once its TTL elapses.
  This is a shipped capability, listed here only to note the one residual
  gap: the block store is per-replica unless `postgres_storage` is also
  on (see [HA deployment](/features/ha-deployment/)).
