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
