package domain

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
}
