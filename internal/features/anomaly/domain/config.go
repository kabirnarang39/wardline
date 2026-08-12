package domain

// MLScoreConfig configures the combined-z-score ML detector, which
// reuses Detector's existing per-identity state and window -- it has
// no window of its own. ScoreThreshold is compared against
// max(|z_rate|, |z_diversity|, |z_deny|, |z_interarrival|). MinCalls
// gates the entire feature on the previous completed window's call
// count -- below it, none of the four features are scored or folded
// into their baselines. This exists for the same reason
// RateMinCalls/DenyRateMinCalls exist on the other two heuristics: a
// window with too few calls can't say anything trustworthy about
// tool-diversity or inter-arrival spacing: a 1-call window has no
// inter-arrival delta at all, so that feature falls back to 0.0 -- a
// range extreme meaning "no observation," not "wild outlier" -- and
// MinCalls is what keeps such a window from being scored against it.
type MLScoreConfig struct {
	Enabled        bool
	ScoreThreshold float64
	MinCalls       int
}

// AutoBlockConfig configures whether an ml_score or drift_detection
// anomaly also blocks the identity's calls, and for how long.
// Deliberately a stricter, separately-configured threshold from
// MLScoreConfig.ScoreThreshold -- an operator can log at a lower
// sensitivity than they block at. drift_detection uses its own DriftConfig.H
// as its decision threshold rather than this one (the two statistics
// are on different scales -- a per-window z-score vs. a cumulative sum
// -- so sharing one threshold value between them would make one of the
// two meaningless); this field's Enabled/BlockDurationSeconds are
// shared by both.
type AutoBlockConfig struct {
	Enabled              bool
	ScoreThreshold       float64
	BlockDurationSeconds int
}

// DriftConfig configures the drift-detection heuristic: a one-sided
// CUSUM (cumulative sum) control chart over the call_rate feature,
// closing the gap ml_score's own per-window z-score test cannot --  a
// slow, sustained rise where no single window looks anomalous on its
// own, but the cumulative deviation from baseline is real (see
// docs/features/anomaly-detection.md's "Known limitations" and "Recall
// benchmark" sections, and TestDetector_AutoBlock_LowAndSlowEvades).
// CUSUM is the standard, decades-proven statistical-process-control
// technique for exactly this: a per-sample test like ml_score is
// provably strong against large abrupt shifts and provably weak
// against small sustained ones, which is why intrusion-detection
// literature treats CUSUM/EWMA as the complement to a per-sample test,
// not a replacement for it.
//
// Requires MLScore.Enabled: this heuristic reuses ml_score's own
// call_rate baseline (mlFeatureState.rate) rather than duplicating a
// second one, so there is nothing for it to score against if ml_score
// itself never builds that baseline up.
//
// K is the CUSUM "allowance" (in units of the baseline's own standard
// deviation) -- how large a per-window deviation is subtracted before
// accumulating, which sets how large a *sustained* shift this is tuned
// to catch quickly. H is the decision threshold the running cumulative
// sum must exceed to alarm. Montgomery's Introduction to Statistical
// Quality Control recommends K=0.5 (tuned for a ~1-sigma sustained
// shift) and H=4-5 as a combination with good false-alarm/detection-
// speed tradeoff properties; the shipped example config uses the more
// conservative H=5, matching this package's existing bias toward
// protecting the false-positive budget over faster detection (see
// online_stat.go's minSamplesForZScore/minStddevRelFraction doc
// comments for the same posture elsewhere in this detector).
type DriftConfig struct {
	Enabled  bool
	K        float64
	H        float64
	MinCalls int

	// HJitterFraction, when > 0, perturbs each identity's own effective H
	// by up to this fraction (e.g. 0.2 = ±20%), deterministically derived
	// per identity from HMAC-SHA256(JitterSecret, identity) -- a moving-
	// target defense against an attacker who has read this exact
	// threshold off the public docs/source and calibrated a "sustained
	// rate just under H" attack to it (see
	// TestAdversarialBenchmark_MimicryCeiling). Requires JitterSecret;
	// without a secret the same computation is attacker-reproducible and
	// provides no real uncertainty. Documented honestly, not oversold:
	// published moving-target-defense research shows this class of
	// defense raises the cost of a static, source-derived attack but is
	// substantially weaker against an *adaptive* attacker who can probe
	// the live system repeatedly to infer the actual effective threshold
	// -- see docs/features/anomaly-detection.md's "Adversarial scenarios"
	// section for the citation and the honest framing.
	HJitterFraction float64
	// JitterSecret is the per-deployment secret HJitterFraction's HMAC is
	// keyed on -- loaded by the composition root from
	// platform/config.DriftConfig.JitterSecretFile, the same
	// never-inline-a-secret pattern federation.SharedSecretFile already
	// uses for its own HMAC (see federation/domain.Fingerprint).
	JitterSecret []byte
}

// TenantAnomalyConfig configures tenant-aggregate rate detection: a
// separate baseline over the SUM of every identity's call volume within
// a tenant, per window -- closing a gap no per-identity heuristic can
// close by construction (see TestAdversarialBenchmark_DistributedSybil).
// Detection-only: there is no single identity to auto-block for a
// tenant-level signal, so this only ever logs, the same posture
// deny_rate_spike already has. HA-safe when features.postgres_storage is
// also on: window totals merge atomically across replicas via
// PostgresTenantWindowStore (see NewDetectorWithTenantStores); falls
// back to per-replica, in-memory-only aggregation otherwise.
type TenantAnomalyConfig struct {
	Enabled        bool
	RateMultiplier float64
	MinCalls       int
}

// IdentityChurnConfig configures identity-churn detection: a baseline
// over the COUNT of never-before-seen identities appearing within a
// tenant, per window -- a different signal from TenantAnomalyConfig's
// call-volume sum. Exists to close a gap no per-identity heuristic can
// close by construction, the same way TenantAnomalyConfig does for call
// volume: any per-identity defense that derives a value from the
// identity itself (rate_spike's own baseline, novel_tool's per-identity
// tool set, and especially DriftConfig.HJitterFraction's per-identity
// jitter) is a coin flip an attacker who can mint disposable identities
// gets to keep re-rolling, discarding whichever identity got caught and
// trying a fresh one -- see docs/superpowers/specs/2026-08-12-identity-
// churn-design.md for the full research and why a per-identity fix
// (e.g. gating jitter on identity tenure) cannot close this by
// construction: zCount already returns 0 before an identity clears
// minSamplesForZScore windows of history, so any tenure gate has
// nothing left to gate by the time the exploit becomes live. The
// production-grade answer, matching real fraud/bot-mitigation practice
// (new-account-velocity and session-churn-rate signals), is to detect
// the rotation itself, aggregated above the identity level.
//
// Detection-only, same reasoning as TenantAnomalyConfig: there is no
// single identity to auto-block for a churn signal (the whole point is
// that no single identity's behavior is what's anomalous). Postgres-
// backed HA sharing (window-total merge + baseline persistence) is
// available when features.postgres_storage is also on -- see
// adapter.PostgresChurnWindowStore/PostgresChurnBaselineStore, wired the
// same way TenantAnomalyConfig's own two stores are.
type IdentityChurnConfig struct {
	Enabled          bool
	RateMultiplier   float64
	MinNewIdentities int

	// CUSUMEnabled turns on a cumulative-sum control-chart extension over
	// identity_churn's own per-window totals -- same arithmetic
	// drift_detection's call_rate/tool_diversity CUSUM already uses
	// (S_t = max(0, S_{t-1}+z-K); alarms when S_t>H, see cusumStep),
	// applied here to the tenant-level churn count instead of a
	// per-identity feature. Closes the slow-trickle gap a plain
	// per-window RateMultiplier test can't: one new disposable identity
	// every many windows, individually below MinNewIdentities/
	// RateMultiplier every single window, but a sustained rate CUSUM
	// still accumulates toward and eventually crosses H -- see
	// docs/superpowers/specs/2026-08-12-identity-churn-design.md's "out
	// of scope" section, which named this exact extension as the
	// documented next step, not a new mechanism to invent.
	//
	// Independent of DriftConfig.Enabled and its own K/H: identity_churn
	// is a tenant-level signal with no single identity to jitter H
	// against (DriftConfig.HJitterFraction is meaningless here), so it
	// gets its own K/H rather than reusing or requiring drift_detection
	// to be on.
	CUSUMEnabled bool
	K            float64
	H            float64
}

// HeuristicConfig configures all anomaly-detection heuristics. Each
// heuristic has its own Enabled switch so an operator running a
// single well-known automation identity and one fronting hundreds of
// dynamic agent identities can each turn on only what fits their traffic
// shape. RateSpikeEnabled and DenyRateSpikeEnabled share WindowSeconds --
// both are volumetric counts over the same identity traffic, so this
// cycle deliberately uses one trailing window per identity rather than
// two independently-sized ones (see design doc "Config").
type HeuristicConfig struct {
	WindowSeconds int

	RateSpikeEnabled bool
	RateMultiplier   float64
	RateMinCalls     int

	NovelToolEnabled bool

	DenyRateSpikeEnabled bool
	DenyRateThreshold    float64
	DenyRateMinCalls     int

	MLScore       MLScoreConfig
	AutoBlock     AutoBlockConfig
	Drift         DriftConfig
	TenantAnomaly TenantAnomalyConfig
	IdentityChurn IdentityChurnConfig
}
