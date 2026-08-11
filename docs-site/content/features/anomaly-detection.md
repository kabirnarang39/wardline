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
  drift_detection: {enabled: true, k: 0.5, h: 5.0, min_calls: 5}
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

## Drift detection (CUSUM)

`ml_score` scores each window independently against its own baseline —
that's exactly what makes it strong against abrupt spikes and exactly
what makes it blind to a slow, sustained ramp (see "Known limitations"
below): no single window in a gradual climb looks unusual relative to
the baseline the *previous* windows just established. `drift_detection`
closes that specific gap with a different, complementary statistic: a
one-sided CUSUM (cumulative sum) control chart over the `call_rate`
feature.

CUSUM is not a novel technique — it's the standard, decades-old
statistical-process-control tool for exactly this failure mode, and
network-intrusion-detection literature treats it as the de facto
workhorse for sequential change-point detection specifically because a
per-sample test (like `ml_score`'s own z-score) is provably strong
against large abrupt shifts and provably weak against small sustained
ones. Rather than scoring each window in isolation, it accumulates:

```
S_t = max(0, S_{t-1} + z_t - k)
```

where `z_t` is this window's standardized `call_rate` deviation (the
same value `ml_score`'s own `zRate` uses — one shared baseline, not a
duplicated one) and `k` is the "allowance": how large a *sustained*
per-window deviation gets subtracted before accumulating. The running
sum resets to 0 on any window at or below the allowance, and alarms
when it exceeds the decision threshold `h`. `k=0.5` / `h=4.0`–`5.0` are
Montgomery's *Introduction to Statistical Quality Control* standard
recommendation (tuned to detect roughly a 1-sigma sustained shift); this
feature's shipped example uses the more conservative `h=5.0`, matching
this detector's existing bias toward protecting the false-positive
budget over faster detection (see `minSamplesForZScore`/
`minStddevRelFraction` above).

Requires `ml_score.enabled` — `drift_detection` reuses `ml_score`'s own
`call_rate` baseline rather than building a second one, so there's
nothing for it to score against if `ml_score` never builds that baseline
up.

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

**Abrupt spike** — single-window spike at N× a ~30 calls/window baseline, 20 independent trials per multiple, with and without `drift_detection`:

| Spike | Recall (`ml_score`/`auto_block` only) | Recall (+ `drift_detection`) |
|---|---|---|
| 1.5× | 0% | 0% |
| 2× | 0% | 55% |
| 3× | 100% | 100% |
| 5× | 100% | 100% |
| 10× | 100% | 100% |
| 20× | 100% | 100% |

Without `drift_detection`, detection is a step function: nothing below
3× the identity's own baseline blocks, everything at or above it does.
`drift_detection` narrows that gap but doesn't close it — an
unplanned finding while building the adversarial scenarios below: a
single 2× window can push an *already slightly positive* CUSUM
accumulator (ordinary residual from warmup noise) over the decision
threshold in one step, without any ramp at all. 1.5× stays a clean 0%
recall either way — confirmed, not assumed, since it's load-bearing for
the sybil finding below.

**Low-and-slow** — ramp rate = +N calls/window from the same baseline, up to a 150-window ceiling, with and without `drift_detection`:

| Ramp | `ml_score`/`auto_block` only | + `drift_detection` |
|---|---|---|
| +1/window | never blocked (150 windows, reached 6.0× baseline) | blocked at window 10 (1.4× baseline) |
| +2/window | never blocked (150 windows, reached 11.0× baseline) | blocked at window 6 (1.5× baseline) |
| +3/window | never blocked (150 windows, reached 16.0× baseline) | blocked at window 4 (1.5× baseline) |
| +5/window | blocked at window 9 (2.7× baseline) | blocked at window 3 (1.7× baseline) |
| +10/window | blocked at window 4 (2.7× baseline) | blocked at window 2 (2.0× baseline) |

Without `drift_detection`, the blind spot has a real, measured edge, not
just a qualitative "exists": a ramp of +3 calls/window or slower evaded
detection entirely through 150 windows and 16× the original call rate.
`drift_detection` closes this specific gap — even the gentlest tested
ramp (+1/window, the slowest, most patient shape in this benchmark) now
blocks within 10 windows, at only 1.4× baseline. The mechanism: a
Welford running mean's lag behind a sustained linear trend *grows* as
more windows accumulate (its effective responsiveness decreases with
sample count), so each window's standardized deviation from that
increasingly-lagging baseline climbs steadily — exactly the small,
persistent, growing bias CUSUM is built to accumulate past its decision
threshold. Verified directly against per-window instrumentation, not
inferred from the block/no-block outcome alone.

**Deny-rate spike** — single-window deny ratio, 20 trials per rate. `deny_rate_spike` (always logs, never blocks on its own) vs. `ml_score`/`auto_block`:

| Deny ratio | Flagged | Auto-blocked |
|---|---|---|
| 20% | 20/20 | 0/20 |
| 40% | 20/20 | 20/20 |
| 60% | 20/20 | 20/20 |
| 80% | 20/20 | 20/20 |
| 100% | 20/20 | 20/20 |

`deny_rate_spike` fires reliably at every tested ratio, matching its
design (no window-completion gate). Auto-block is a clean step function
above 20%, but it wasn't always this clean: an earlier run of this
benchmark showed noisy, non-monotonic auto-block recall (40% blocked
only 12/20 trials, 80% only 8/20) — a *higher*-severity attack blocking
*less* reliably than a lower one. Direct instrumentation traced this to
`maxHarmfulZ`'s deny-ratio volume-decline gate: it excluded an
already-correctly-scored, severe `deny_ratio` candidate (z=9.57, well
past the 8.0 auto_block threshold) whenever an *unrelated* feature
(`toolCalls`, whose value in this scenario sits within noise of its own
baseline mean, since a deny-rate attack doesn't itself change call
volume) had a negative z-score — a coin flip driven by warmup sampling
noise, not by attack severity. Fixed by giving the gate a one-sigma
hysteresis margin (`volumeDeclineMargin` in `detector.go`) instead of a
bare zero cutoff, so noise within 1 standard deviation of the baseline
no longer silently vetoes a real anomaly on a different feature. Full
regression suite, including the 0% false-positive result below, is
unchanged by the fix.

**Novel-tool enumeration** — single-window burst of brand-new distinct tools, 20 trials per size:

| Burst | Recall |
|---|---|
| 2 | 0% |
| 5 | 0% |
| 10 | 0% |
| 20 | 0% |
| 40 | 100% |

Unlike the deny-rate result above, this step function is *not* a gate
artifact — verified directly against `zCount`'s own floor formula
(`max(1, sqrt(baseline mean))`): with this scenario's ~6-tool baseline
diversity, the auto_block threshold requires roughly `6 + 8×√6 ≈ 26`
new tools in one window, which lands exactly between the tested 20
(0%) and 40 (100%) points. `tool_diversity`'s baseline mean is much
smaller than `call_rate`'s (~30), so it needs a *larger* relative
multiple to trigger the same shared z-threshold — the expected
consequence of a Poisson-style `√mean` variance floor applied to
features at very different scales, not a miscalibration to fix.

**False-positive rate** — 20 independent identities/seeds, 300 windows each (6,000 windows total) of steady ~30 calls/window traffic with ±20% jitter, post-warmup: **0/6,000 flagged (0.00%)** with `ml_score`/`auto_block` alone, and **still 0/6,000** with `drift_detection` also on — closing the low-and-slow gap cost nothing measured here.

This is one synthetic corpus against the shipped example config, not an
independent red-team evaluation. The adversarial scenarios below go
further — attack *shapes* constructed to probe the architecture itself,
not just severity curves.

## Adversarial scenarios

Reproduce with:

```bash
go test ./internal/features/anomaly/usecase/ -run TestAdversarialBenchmark -v
```

These are attacks a real adversary with this repository open in another
tab could construct — every threshold, every formula, is public. Results
are reported honestly whichever way they land: an evasion that succeeds
is exactly as important to publish as a detection that succeeds.

**Distributed / sybil.** Every per-identity heuristic in this package
baselines per `(tenant, identity)`. 20 independent identities each
individually performing the confirmed-0%-recall 1.5× abrupt spike,
simultaneously: **0/20 individually blocked**, 900 calls of aggregate
attack volume in one window, entirely invisible as a *combined* event to
any per-identity heuristic — none of them look across identities at all.
[federation](/features/federation/) doesn't close this either: it
correlates alert *counts* across Wardline instances, never raw
per-identity call history across identities on the same instance.

*Mitigation: `tenant_anomaly`.* A dedicated heuristic that baselines the
*sum* of every identity's call volume within a tenant, independent of
any single identity's own state — the same "aggregate baseline,
per-identity baseline" pattern application-layer DDoS and account-level
anomaly detection systems already use. Re-running the identical 20-
identity, 1.5× scenario with `tenant_anomaly` also on: the tenant
aggregate scores **z=17.86** against its own baseline (threshold 5.0) —
clearly flagged and logged, even though every one of the 20 identities
still individually evades. This works because independent per-identity
noise partially cancels in the sum (the law of large numbers shrinks the
aggregate's *relative* noise by roughly √20 versus any one contributor's
own), while a coordinated shift across all of them does not cancel — the
same multiplicative attack that's invisible against one identity's own
noise floor stands out clearly against the tenant's much tighter one.
Verified false-positive-safe too: 0/1,000 tenant-windows flagged across
10 tenants × 20 identities × 100 windows of steady traffic.

Still honestly scoped: `tenant_anomaly` **logs, it never auto-blocks** —
there is no single identity to block for a tenant-level signal, so this
closes the *visibility* gap (an operator can now see and act on a sybil
attack) without claiming an automated response to it. Building the
scoring function required a real fix along the way: the first version
reused `ml_score`'s existing per-feature z-score helper, whose 15%-of-
mean relative floor is correctly tuned for small per-identity baselines
but — left in place at tenant-aggregate scale (mean ≈ 600 for a
20-identity tenant) — grows large enough to swallow the very
tighter-noise advantage aggregation is supposed to provide, scoring the
identical attack at z=3.39 instead of z=17.86 and missing it entirely
against a 5.0 threshold. `tenant_anomaly` uses its own scoring function
without that floor.

**Mimicry ceiling.** An attacker who has read `k=0.5` off this exact
page can ask: what's the highest *sustained* (constant, non-ramping)
elevated rate that survives forever against the full config —
`ml_score` + `auto_block` + `drift_detection` all on? Swept from 1.05×
to 1.50× baseline, held for up to 300 windows:

| Sustained rate | Result |
|---|---|
| 1.05× | survived 300 windows |
| 1.10× | survived 300 windows |
| 1.15× | survived 300 windows |
| 1.20× | blocked at window 7 |
| 1.25× | blocked at window 7 |
| 1.30× | blocked at window 5 |
| 1.40× | blocked at window 3 |
| 1.50× | blocked at window 2 |

A CUSUM accumulates `z - k` every window, so any sustained deviation
above `k` climbs without bound and must eventually cross `h` — there is
no rate elevation that evades *indefinitely* except one whose z-score
sits at or below `k` permanently. **~1.15× baseline, held forever, is
that ceiling** for the shipped example config. This is the honest,
measured answer to "how much room does an attacker who's read the
source have" — not a guess.

**Why this ceiling can't be engineered away, and what actually closes
it.** This isn't a Wardline-specific gap waiting on more engineering —
it's the defining property of the allowance `k` in *any* CUSUM/EWMA-
style sequential detector (Page's original 1954 formulation; see
Lucas & Crosier's ARL analysis for the formal treatment): `k` sets the
boundary between "ordinary noise, ignore it" and "sustained shift,
accumulate toward an alarm," and a deviation that never exceeds `k` is
*by construction* the one class of shift the statistic cannot
distinguish from noise in bounded time. Driving `k` toward zero to
close this doesn't fix it — it just turns the detector into a
per-window test with no memory, alarming on ordinary noise and
collapsing the false-positive budget every heuristic in this package is
held to. This is the same Neyman-Pearson sensitivity/false-alarm
tradeoff underlying every real anomaly/intrusion-detection system, not
a defect unique to this implementation.

What actually closes the operating room a mimicry attacker has is
exactly what this package already ships, not a hypothetical future
statistic: `h_jitter_fraction` (raises the cost of an attack calibrated
to the *public default* `k`/`h`, measured above); `tenant_anomaly` and
`identity_churn` (a sustained 1.15× shift held by one identity forever
is invisible to per-identity CUSUM, but an attacker running it across
*many* identities to make it worthwhile is exactly what those two
heuristics are built to catch — see their own sections above); and,
underneath all of it, explicit policy and budget limits, which bound
absolute behavior regardless of what any statistical detector does or
doesn't catch — the recommendation this doc has given from the start,
not a fallback added to paper over this ceiling. Defense in depth, not
one detector expected to close every gap alone.

*Mitigation: `h_jitter_fraction`.* Perturbing each identity's own `h` by
±20% (`h_jitter_fraction: 0.2`, keyed by a per-deployment secret — see
"Drift detection" above) genuinely changes this outcome, re-measured at
the same three multiples across 30 identities each:

| Sustained rate | Unjittered | With `h_jitter_fraction: 0.2` |
|---|---|---|
| 1.10× | 0/30 caught | 0/30 caught (still universally safe) |
| 1.15× | 0/30 caught (the "safe forever" ceiling) | **7/30 caught** (23%), within 9–19 windows |
| 1.20× | 30/30 caught | 27/30 caught (90% — a few individual identities' jittered `h` landed higher, surviving slightly longer) |

This is a real, measured effect, not a placebo — an attacker calibrated
to the public default `h=5.0` now has a genuine, non-zero chance of
being caught at a rate that was previously safe with certainty. It is
**not** a full close of the gap: this is a standard moving-target
defense (DHS's own definition — "controlling change across multiple
system dimensions in order to increase uncertainty ... for attackers" —
applies directly), and published MTD research on adversarial-detection
evasion reports such defenses can still suffer very high evasion rates
against an *adaptive* attacker who can repeatedly query the live system
to infer their own effective threshold, as opposed to a one-shot
attacker calibrated only from the published source ("Effectiveness of
Moving Target Defenses for Adversarial Attacks in ML-Based Malware
Detection," 2023). Advertised honestly as "raises the bar for a
source-derived attack," not "solved."

**`h_jitter_fraction`'s own vulnerability — and why it can't be
patched away in isolation.** Jitter is a per-identity coin flip: an
attacker who can mint disposable identities doesn't need to win it on
any specific identity, only *once*, then keeps whichever identity's
draw was favorable and discards the rest. With even a handful of
throwaway identities, the odds of finding at least one favorable draw
climb fast. This is true of *any* threshold discoverable only by trial
against cheap disposable identities — not a flaw in the jitter formula
itself, and not fixable by tuning it (a tenure-based gate was
considered and rejected: `zCount` already returns `0` before an
identity clears `minSamplesForZScore`'s 8-window floor, so by the time
jitter is live at all, an attacker willing to pay that setup cost per
identity was always going to pay it).

*Mitigation: `identity_churn`.* The actual fix, matching real
fraud/bot-mitigation practice (new-account-velocity and session-churn
signals in production fraud scoring and bot management), is the same
resolution `tenant_anomaly` reached for coordinated call volume: no
per-identity mechanism can close a disposable-identity gap by
construction, so detect the *rotation itself*, aggregated above the
identity level. `identity_churn` baselines the count of
never-before-seen identities appearing in a tenant per window; a burst
far above that tenant's normal new-identity rate is the fingerprint of
an attacker discarding caught identities and retrying fresh ones —
regardless of which per-identity heuristic they were trying to roll
against. Measured directly: 30 throwaway identities appearing in a
single window, each making an entirely ordinary number of calls (no
per-identity heuristic has any baseline yet to compare a brand-new
identity's first window against) — **0/30 individually caught by any
per-identity heuristic, `identity_churn` flagged the window** (see
`TestAdversarialBenchmark_DisposableIdentityRotation`). Detection-only,
same "no single identity to block" reasoning as `tenant_anomaly`, and
in-memory only this cycle — see [Known limitations](#known-limitations).

**Burst-pause duty cycling.** Does alternating a high-volume window with
a quiet one defeat detection by exploiting CUSUM's own reset-on-decline
behavior? Tested at 3×, 5×, and 10× baseline bursts, each followed by one
quiet window, repeating: **all three blocked on the very first burst
window** (cycle 0) — the burst itself is already past the abrupt-spike
detection threshold before any pause has a chance to matter. Bursts at
this severity don't benefit from pausing; a lower-severity duty cycle
(bursts in the 1.5×-2× range, where single-shot detection is itself
inconsistent) is a natural next scenario this benchmark doesn't cover
yet.

**Slow novel-tool drip.** `novel_tool` logs on every first-ever sighting
of a tool, unconditionally, regardless of pace — so an identity calling
exactly one brand-new tool per window is logged every single time (151
`novel_tool` anomalies over 150 windows, confirmed). Auto-block, though,
depended on `ml_score`'s `tool_diversity` feature, which only escalates
from a *burst* of new tools in one window (see the novel-tool-enumeration
table above) — a one-per-window drip never moved any single window's
diversity count far enough above baseline to cross a per-window
threshold, so this evaded auto-block indefinitely against `ml_score`
alone.

*Partial mitigation: `drift_detection` now also scores
`tool_diversity`* — `checkDrift` runs an independent CUSUM accumulator
over it using the same K/H as `call_rate` (a standardized z-score is
scale-free, it doesn't matter which feature it came from). No separate
config key, on whenever `drift_detection.enabled` is. Tested honestly
against both shapes of this attack, not just the one that makes the
number look good:

- **A *growing* enumeration ramp** (1 new tool in window 1, 2 in window
  2, 3 in window 3, ...) — the same "ever-moving target the baseline
  mean can never fully catch up to" shape that closes the `call_rate`
  low-and-slow gap — **is caught, at window 5** (only 6 new tools in the
  triggering window).
- **The flat, constant 1-new-tool-per-window drip above is not** —
  re-confirmed with `drift_detection` on, still never auto-blocked in
  150 windows. The reason CUSUM doesn't help here is structural, not a
  tuning gap: a *constant* offset above baseline gets folded into
  `tool_diversity`'s own baseline mean within a handful of windows (the
  same "unflagged windows fold, absorbing the shift" mechanism that
  causes the original low-and-slow limitation), so the standardized
  deviation *shrinks* back toward zero rather than growing the way a
  true ramp's does. CUSUM accumulates a persistent *growing* bias; a
  drip that never accelerates isn't one.

## Known limitations

- **Low-and-slow evasion — true of `ml_score`/`auto_block` alone,
  substantially (not completely) closed by `drift_detection`.** Because
  `ml_score`'s baseline is self-learned per identity (Welford,
  unsupervised) and scores each window in isolation, an attacker who
  ramps activity gradually — staying within a few standard deviations of
  the moving baseline each window — is never auto-blocked by `ml_score`
  alone: the baseline adapts upward and absorbs the ramp. This is an
  inherent tradeoff of a per-window test, not a tunable threshold
  (tightening `ml_score.score_threshold` would raise the false-positive
  rate the detector is regression-guarded to keep near zero) — pinned by
  `TestDetector_AutoBlock_AbruptSpikeIsBlocked` and
  `TestDetector_AutoBlock_LowAndSlowEvades`, and still exactly true
  whenever `drift_detection.enabled` is `false`.
  With `drift_detection` on (the config example at the top of this page
  enables it), this is a different, much better picture — see "Recall
  benchmark" above for the real numbers: even the gentlest tested ramp
  blocks within 10 windows at 1.4× baseline. The residual gap is
  quantified, not hand-waved: `TestAdversarialBenchmark_MimicryCeiling`
  finds a real ~1.15× sustained-forever ceiling for an attacker who
  knows the public default `k`/`h`, narrowed further (not eliminated) by
  `h_jitter_fraction` — see "Adversarial scenarios." Pair anomaly
  detection with explicit policy and budget limits regardless, which
  bound absolute behavior no matter what any statistical detector does
  or doesn't catch.
- **Cross-identity correlation — partially closed by `tenant_anomaly`,
  not by federation.** Every heuristic above (including
  `drift_detection`) still baselines per `(tenant, identity)` alone;
  [federation](/features/federation/) correlates *alert counts* across
  Wardline instances, never raw per-identity call history, so it was
  never going to close this. `tenant_anomaly` (see "Adversarial
  scenarios") closes the specific gap those two leave: a coordinated
  spike spread across many identities *in the same tenant* — confirmed
  via a real 20-identity test that individually evades every
  per-identity heuristic while scoring z=17.86 in aggregate. With
  `postgres_storage` also on, this now holds whether that traffic lands
  on one replica or is split across many by a load balancer — verified
  against a real Postgres instance with two real `Detector`s, each
  seeing only half the spike, catching it via their shared merged total
  (see the HA note below). What's still open: identities spread across
  *different* tenants (by design — see `tenant_anomaly`'s own scoping),
  and `tenant_anomaly` only ever logs, it does not auto-block (there is
  no single identity to block for a tenant-level signal).
- `identity_churn` is now HA-safe when `postgres_storage` is also on —
  same shape as `tenant_anomaly`'s own HA extension: each replica
  upserts its own just-finished window's local new-identity count into
  a shared `identity_churn_window_totals` row and every replica scores
  and folds the *merged, cross-replica* total into its baseline, so a
  disposable-identity rotation attack split across replicas by a load
  balancer is caught the same way it's caught split across identities
  on one instance — verified against a real Postgres instance with two
  real `Detector`s, neither replica's own local half of a split
  rotation burst alone crossing the threshold, only the merged total.
  `identity_churn` also now has a CUSUM extension
  (`identity_churn.cusum_enabled`, its own `k`/`h`, independent of
  `drift_detection`'s) closing the slow-trickle gap a plain per-window
  count can't: one new disposable identity every many windows,
  individually always below `rate_multiplier`, still accumulates toward
  and crosses the CUSUM threshold — same `cusumStep` mechanics
  `drift_detection` already uses for `call_rate`/`tool_diversity`, not
  new machinery. Without `postgres_storage`, `identity_churn` is
  in-memory only, per-replica — a rotation attack split across replicas
  by a load balancer dilutes each replica's own view of the burst, the
  same gap `tenant_anomaly` has without `postgres_storage` too.
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
- `tenant_anomaly` is now HA-safe when `postgres_storage` is also on: each
  replica upserts its own just-finished window's local total into a
  shared `tenant_window_totals` row (one atomic `INSERT ... ON CONFLICT
  DO UPDATE ... RETURNING` round trip, keyed on `(tenant, window_start)`)
  and every replica scores and folds the *merged, cross-replica* total
  into its baseline — never its own local-only delta — so a coordinated
  spike split across replicas by a load balancer is caught by the same
  z-score logic that already catches it split across identities on one
  instance. Verified against a real Postgres instance with two real
  `Detector`s: neither replica's own local half of a split spike alone
  crossed the threshold, only the merged total did. The per-tenant
  running baseline itself (mean/variance) still persists per-instance
  only, in a separate `tenant_baselines` table keyed `(instance_id,
  tenant)` — deliberately not shared row-for-row the way the window
  totals are, since every replica converges to the same baseline by
  folding the same merged total, not by reading each other's baseline
  state directly. Without `postgres_storage` on, `tenant_anomaly` falls
  back to today's in-memory, per-replica-only behavior (a startup log
  line says so explicitly). `drift_detection`'s own CUSUM accumulators
  are part of `identityState` and already follow the same
  Postgres-backed persistence as the rest of `ml_score`'s baseline.
- Currently-blocked identities are surfaced both as the `GET
  /dashboard/api/anomalies/blocked` JSON API and, when `web_ui` is on, a
  dedicated **Blocked** panel in the dashboard. A block can be cleared
  early via `DELETE /dashboard/api/anomalies/blocked/{identity}`, gated
  by the same `credential:revoke` permission as credential revocation
  (when `rbac` is on) — otherwise it simply expires once its TTL elapses.
  This is a shipped capability, listed here only to note the one residual
  gap: the block store is per-replica unless `postgres_storage` is also
  on (see [HA deployment](/features/ha-deployment/)).
