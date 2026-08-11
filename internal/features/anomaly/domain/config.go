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
// deny_rate_spike already has. In-memory only for this cycle -- unlike
// identityState, tenant aggregate baselines do not yet persist to
// Postgres.
type TenantAnomalyConfig struct {
	Enabled        bool
	RateMultiplier float64
	MinCalls       int
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
}
