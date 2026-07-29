package usecase

import "math"

// onlineStat maintains a running mean and variance via Welford's
// algorithm: O(1) update, O(1) memory, no stored history. Used as each
// identity's per-feature baseline for the ml_score detector -- the same
// "self-baselining, not a hardcoded global threshold" property
// rate-spike already has, generalized to a continuous z-score instead
// of one ratio-based threshold.
type onlineStat struct {
	mean  float64
	m2    float64
	count int64
}

// Update folds x into the running mean/variance.
func (s *onlineStat) Update(x float64) {
	s.count++
	delta := x - s.mean
	s.mean += delta / float64(s.count)
	delta2 := x - s.mean
	s.m2 += delta * delta2
}

// ZScore reports how many standard deviations x is from the running
// mean. Returns 0 (never anomalous) when there isn't enough history yet
// (fewer than 2 samples) or the running variance is zero (every prior
// sample was identical) -- both are "not enough signal to judge",
// treated as the conservative non-anomalous case rather than an
// undefined division.
func (s *onlineStat) ZScore(x float64) float64 {
	if s.count < 2 {
		return 0
	}
	variance := s.m2 / float64(s.count-1)
	if variance <= 0 {
		return 0
	}
	stddev := math.Sqrt(variance)
	return (x - s.mean) / stddev
}
