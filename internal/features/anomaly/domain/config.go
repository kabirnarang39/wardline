package domain

// MLScoreConfig configures the combined-z-score ML detector, which
// reuses Detector's existing per-identity state and window -- it has
// no window of its own. ScoreThreshold is compared against
// max(|z_rate|, |z_diversity|, |z_deny|, |z_interarrival|).
type MLScoreConfig struct {
	Enabled        bool
	ScoreThreshold float64
}

// AutoBlockConfig configures whether an ml_score anomaly also blocks
// the identity's calls, and for how long. Deliberately a stricter,
// separately-configured threshold from MLScoreConfig.ScoreThreshold --
// an operator can log at a lower sensitivity than they block at.
type AutoBlockConfig struct {
	Enabled              bool
	ScoreThreshold       float64
	BlockDurationSeconds int
}

// HeuristicConfig configures all three anomaly-detection heuristics.
// Each heuristic has its own Enabled switch so an operator running a
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

	MLScore   MLScoreConfig
	AutoBlock AutoBlockConfig
}
