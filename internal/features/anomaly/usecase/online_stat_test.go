package usecase

import (
	"math"
	"testing"
)

func TestOnlineStat_MeanAndVariance_MatchHandComputed(t *testing.T) {
	var s onlineStat
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9} // classic Welford's example: mean 5, population variance 4
	for _, v := range values {
		s.Update(v)
	}
	if math.Abs(s.mean-5.0) > 1e-9 {
		t.Errorf("expected mean 5.0, got %v", s.mean)
	}
	variance := s.m2 / float64(s.count)
	if math.Abs(variance-4.0) > 1e-9 {
		t.Errorf("expected population variance 4.0, got %v", variance)
	}
}

func TestOnlineStat_ZScore_ZeroForMeanValue(t *testing.T) {
	var s onlineStat
	for i := 0; i < 10; i++ {
		s.Update(10.0)
	}
	// stddev is 0 here (all identical values) -- ZScore must not divide
	// by zero; a value equal to the mean should read as "not anomalous".
	if z := s.ZScore(10.0); z != 0 {
		t.Errorf("expected z-score 0 for a value equal to a zero-variance mean, got %v", z)
	}
}

func TestOnlineStat_ZScore_LargeForOutlier(t *testing.T) {
	var s onlineStat
	for i := 0; i < 20; i++ {
		s.Update(10.0)
	}
	s.Update(11.0)
	s.Update(9.0) // small spread introduced so stddev is non-zero
	z := s.ZScore(1000.0)
	if z < 3 {
		t.Errorf("expected a large z-score for a wild outlier, got %v", z)
	}
}

// TestOnlineStat_ZScore_RelativeFloorSuppressesProportionalNoise is the
// regression gate for N1's remainder: minSamplesForZScore alone only
// delayed the false positive, it did not remove it. Hand-computed on the
// reviewer's exact repro -- baseline {10, 11} alternating x8, so mean
// 10.5 and m2 = 8*0.25 = 2.0, giving sample variance 2.0/7 = 0.285714 and
// sample stddev 0.534522. Unfloored, a window of 13 calls (a 24%
// increase) scores (13-10.5)/0.534522 = 4.677, above the shipped example
// config's auto_block.score_threshold of 4.0. Floored at
// 0.15*10.5 = 1.575, the same window scores (13-10.5)/1.575 = 1.5873.
func TestOnlineStat_ZScore_RelativeFloorSuppressesProportionalNoise(t *testing.T) {
	var s onlineStat
	for i := 0; i < 8; i++ {
		s.Update(float64(10 + i%2))
	}
	if math.Abs(s.mean-10.5) > 1e-9 {
		t.Fatalf("test setup: expected baseline mean 10.5, got %v", s.mean)
	}
	unfloored := math.Sqrt(s.m2 / float64(s.count-1))
	if math.Abs(unfloored-0.5345224838248488) > 1e-9 {
		t.Fatalf("test setup: expected sample stddev 0.5345224838, got %v", unfloored)
	}
	if z := (13.0 - s.mean) / unfloored; math.Abs(z-4.677071733467427) > 1e-9 {
		t.Fatalf("test setup: expected the unfloored z-score to be 4.677 (the false positive), got %v", z)
	}

	z := s.ZScore(13.0)
	if math.Abs(z-1.5873015873015872) > 1e-9 {
		t.Errorf("expected z=1.5873 for 13 calls against a floored stddev of 1.575, got %v", z)
	}
	if z >= 3.0 {
		t.Errorf("expected an ordinary 24%% traffic increase to stay below even the 3.0 log threshold, got %v", z)
	}
}

// TestOnlineStat_ZScore_RelativeFloorInertOnWideVarianceBaseline proves
// the floor is a floor and not a rescaling: when the real sample stddev
// already exceeds 0.15*mean, ZScore must match the plain
// (x-mean)/stddev formula exactly. Baseline {2,4,4,4,5,5,7,9} has mean 5
// and m2 = 32, so sample stddev = sqrt(32/7) = 2.138, well above the
// 0.15*5 = 0.75 floor.
func TestOnlineStat_ZScore_RelativeFloorInertOnWideVarianceBaseline(t *testing.T) {
	var s onlineStat
	for _, v := range []float64{2, 4, 4, 4, 5, 5, 7, 9} {
		s.Update(v)
	}
	unfloored := math.Sqrt(s.m2 / float64(s.count-1))
	if floor := math.Abs(s.mean) * minStddevRelFraction; unfloored <= floor {
		t.Fatalf("test setup: this baseline's stddev %v must exceed the relative floor %v", unfloored, floor)
	}
	for _, x := range []float64{0, 5, 9, 100} {
		want := (x - s.mean) / unfloored
		if got := s.ZScore(x); math.Abs(got-want) > 1e-12 {
			t.Errorf("ZScore(%v) = %v, want the unfloored %v -- the floor must be inert here", x, got, want)
		}
	}
}

func TestOnlineStat_SingleSample_ZScoreDoesNotPanic(t *testing.T) {
	var s onlineStat
	s.Update(5.0)
	// count == 1 means variance is undefined (m2 == 0, count-1 == 0) --
	// must not divide by zero or panic; 0 is the defined "not enough
	// history yet" sentinel.
	if z := s.ZScore(100.0); z != 0 {
		t.Errorf("expected z-score 0 with only one sample of history, got %v", z)
	}
}
