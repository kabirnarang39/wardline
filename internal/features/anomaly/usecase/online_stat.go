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

// minSamplesForZScore is how many completed windows must be in a
// baseline before its sample stddev is trustworthy enough to divide by.
// A 2- or 3-sample stddev is dominated by whichever way those two or
// three windows happened to fall: the false positive this floor was
// raised to fix had a 2-sample baseline of {10, 11} calls producing
// z=7.78 for a third window of 15 calls, an entirely ordinary 50% swing.
// 8 is the point at which the sample stddev of a roughly-symmetric
// distribution stops swinging by more than about a third from one new
// observation to the next, so a single unusual-but-legitimate window can
// no longer redefine the whole baseline's width.
const minSamplesForZScore = 8

// minStddevRelFraction floors the effective standard deviation at this
// fraction of the running mean's magnitude, so a baseline that happens
// to be naturally tight can't turn an ordinary proportional swing into
// a large z-score. Concretely, the false positive this floor closes: a
// baseline of {10, 11} calls/window (mean 10.5, sample stddev 0.53) is
// tight enough that a window of 13 calls -- a 24% increase, ordinary
// traffic variation -- scores z=4.68 without this floor, above the
// shipped example config's auto_block.score_threshold of 4.0. With a
// 0.15 floor (stddev floored to 0.15*10.5=1.575), that same window
// scores z=(13-10.5)/1.575=1.59 -- comfortably below both the log and
// block thresholds in the example config.
const minStddevRelFraction = 0.15

// ZScore reports how many standard deviations x is from the running
// mean. Returns 0 when there isn't enough history yet (fewer than
// minSamplesForZScore samples). The divisor is floored at
// minStddevRelFraction of the mean's magnitude even when the running
// variance is exactly zero (every prior sample identical) -- a baseline
// that has never varied at all still must not be treated as "nothing
// could ever deviate from it": a raw-count feature whose baseline
// happens to be perfectly constant (e.g. tool_diversity over a
// genuinely fixed tool set) previously returned z=0 unconditionally
// here regardless of how far a later window's value strayed, blind to
// real deviations because no floor was ever reached to compare against.
func (s *onlineStat) ZScore(x float64) float64 {
	return s.ZScoreFloored(x, 0)
}

// ZScoreFloored is ZScore with an additional caller-supplied floor on
// the effective stddev, applied on top of the standard
// minStddevRelFraction floor -- used by deny_ratio's block-gating score
// to also floor at that window's own binomial standard error, which
// minStddevRelFraction alone can't express since it only knows the
// baseline's typical variance, not how many real observations this
// particular window was computed from.
func (s *onlineStat) ZScoreFloored(x, extraFloor float64) float64 {
	if s.count < minSamplesForZScore {
		return 0
	}
	variance := s.m2 / float64(s.count-1)
	stddev := 0.0
	if variance > 0 {
		stddev = math.Sqrt(variance)
	}
	if floor := math.Abs(s.mean) * minStddevRelFraction; stddev < floor {
		stddev = floor
	}
	if extraFloor > stddev {
		stddev = extraFloor
	}
	if stddev == 0 {
		// mean is also 0 and no extra floor was supplied -- there is no
		// scale to measure a deviation against at all. Reachable only from
		// plain ZScore: deny_ratio's block-gating caller always supplies a
		// continuity-corrected binomial SE, precisely so a never-denied
		// baseline is not permanently blind to its first deny spike (see
		// checkMLScore's pSmoothed comment).
		return 0
	}
	return (x - s.mean) / stddev
}

// AggregateZScore is checkTenantDrift's z-score -- deliberately not
// ZScoreFloored. minStddevRelFraction (15% of the mean) exists to
// protect PER-IDENTITY features, whose small, naturally-tight baselines
// (a handful of calls/window) can turn an ordinary proportional swing
// into a large z-score (see minStddevRelFraction's own doc comment).
// At tenant-aggregate scale that floor becomes counterproductive: it
// grows *linearly* with the mean (0.15 x ~600 = ~90 for a 20-identity
// tenant, versus ~4.5 at one identity's own ~30-call baseline),
// completely swallowing the tighter noise floor tenant aggregation
// earns via the law of large numbers -- independent identities' own
// noise partially cancels in the sum, which is exactly what makes
// tenant aggregation useful for catching a coordinated proportional
// shift in the first place. Verified directly: a real, shared 1.5x-
// baseline spike across 20 identities scored z=3.39 through
// ZScoreFloored's relative floor (below a 5.0 threshold -- an earlier,
// bugged version of drift_detection's tenant_anomaly feature) and
// z=12.37 through this one, against the identical underlying data (see
// TestAdversarialBenchmark_DistributedSybil_WithTenantAnomaly).
//
// Floors only at 1.0 absolute (never 0, so a perfectly flat baseline
// isn't divide-by-zero) -- no relative-to-mean floor at all.
func (s *onlineStat) AggregateZScore(x float64) float64 {
	if s.count < minSamplesForZScore {
		return 0
	}
	variance := s.m2 / float64(s.count-1)
	stddev := 0.0
	if variance > 0 {
		stddev = math.Sqrt(variance)
	}
	if stddev < 1.0 {
		stddev = 1.0
	}
	return (x - s.mean) / stddev
}
