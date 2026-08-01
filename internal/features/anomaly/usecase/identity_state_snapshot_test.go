package usecase

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

func TestSnapshotIdentityState_RoundTripsEmptyState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond) // Postgres/JSON round-trip precision
	st := &identityState{
		tools:       make(map[string]struct{}),
		windowStart: now,
		lastSeen:    now,
	}
	snap := snapshotIdentityState(st)
	got := snap.toIdentityState()

	if len(got.tools) != 0 {
		t.Errorf("expected empty tools map, got %v", got.tools)
	}
	if !got.windowStart.Equal(now) {
		t.Errorf("windowStart: got %v, want %v", got.windowStart, now)
	}
	if !got.lastSeen.Equal(now) {
		t.Errorf("lastSeen: got %v, want %v", got.lastSeen, now)
	}
	if got.mlStats.rate.count != 0 {
		t.Errorf("expected zero-value mlStats, got %+v", got.mlStats)
	}
}

func TestSnapshotIdentityState_RoundTripsFullyPopulatedState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	lastCall := now.Add(-5 * time.Second)
	st := &identityState{
		tools:       map[string]struct{}{"read_file": {}, "write_file": {}},
		windowStart: now.Add(-30 * time.Second),
		cur: windowCounts{
			total: 10, toolCalls: 8, deny: 2,
			uniqueTools:     map[string]struct{}{"read_file": {}},
			interArrivalSum: 7 * time.Second,
			interArrivalN:   3,
		},
		prev: windowCounts{
			total: 15, toolCalls: 12, deny: 1,
			uniqueTools:     map[string]struct{}{"read_file": {}, "write_file": {}},
			interArrivalSum: 9500 * time.Millisecond,
			interArrivalN:   5,
		},
		flaggedThisWindow: map[domain.Kind]bool{domain.KindRateSpike: true, domain.KindNovelTool: true},
		lastSeen:          now,
		lastCallAt:        lastCall,
	}
	st.mlStats.rate.Update(10)
	st.mlStats.rate.Update(12)
	st.mlStats.diversity.Update(3)
	st.mlStats.denyRatio.Update(0.1)
	st.mlStats.interArrival.Update(2.5)
	st.mlStats.toolCalls.Update(12)

	snap := snapshotIdentityState(st)
	got := snap.toIdentityState()

	if len(got.tools) != 2 {
		t.Fatalf("expected 2 tools, got %v", got.tools)
	}
	if _, ok := got.tools["read_file"]; !ok {
		t.Error("expected read_file in tools")
	}
	if !got.windowStart.Equal(st.windowStart) {
		t.Errorf("windowStart: got %v, want %v", got.windowStart, st.windowStart)
	}
	if got.cur.total != 10 || got.cur.toolCalls != 8 || got.cur.deny != 2 {
		t.Errorf("cur counts: got %+v", got.cur)
	}
	if got.cur.interArrivalSum != 7*time.Second || got.cur.interArrivalN != 3 {
		t.Errorf("cur inter-arrival: got sum=%v n=%d", got.cur.interArrivalSum, got.cur.interArrivalN)
	}
	if len(got.cur.uniqueTools) != 1 {
		t.Errorf("cur uniqueTools: got %v", got.cur.uniqueTools)
	}
	if got.prev.total != 15 || got.prev.toolCalls != 12 || got.prev.deny != 1 {
		t.Errorf("prev counts: got %+v", got.prev)
	}
	if got.prev.interArrivalSum != 9500*time.Millisecond {
		t.Errorf("prev interArrivalSum: got %v, want %v", got.prev.interArrivalSum, 9500*time.Millisecond)
	}
	if len(got.flaggedThisWindow) != 2 || !got.flaggedThisWindow[domain.KindRateSpike] || !got.flaggedThisWindow[domain.KindNovelTool] {
		t.Errorf("flaggedThisWindow: got %v", got.flaggedThisWindow)
	}
	if !got.lastCallAt.Equal(lastCall) {
		t.Errorf("lastCallAt: got %v, want %v", got.lastCallAt, lastCall)
	}
	if got.mlStats.rate.mean != st.mlStats.rate.mean || got.mlStats.rate.m2 != st.mlStats.rate.m2 || got.mlStats.rate.count != st.mlStats.rate.count {
		t.Errorf("mlStats.rate: got %+v, want %+v", got.mlStats.rate, st.mlStats.rate)
	}
	if got.mlStats.diversity.count != st.mlStats.diversity.count {
		t.Errorf("mlStats.diversity.count: got %d, want %d", got.mlStats.diversity.count, st.mlStats.diversity.count)
	}
	if got.mlStats.denyRatio.count != st.mlStats.denyRatio.count {
		t.Errorf("mlStats.denyRatio.count: got %d, want %d", got.mlStats.denyRatio.count, st.mlStats.denyRatio.count)
	}
	if got.mlStats.interArrival.count != st.mlStats.interArrival.count {
		t.Errorf("mlStats.interArrival.count: got %d, want %d", got.mlStats.interArrival.count, st.mlStats.interArrival.count)
	}
	if got.mlStats.toolCalls.count != st.mlStats.toolCalls.count {
		t.Errorf("mlStats.toolCalls.count: got %d, want %d", got.mlStats.toolCalls.count, st.mlStats.toolCalls.count)
	}
}

func TestIdentityStateSnapshot_JSONRoundTrips(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	st := &identityState{
		tools:             map[string]struct{}{"read_file": {}},
		windowStart:       now,
		flaggedThisWindow: map[domain.Kind]bool{domain.KindMLScore: true},
		lastSeen:          now,
	}
	st.mlStats.rate.Update(5)

	snap := snapshotIdentityState(st)
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded IdentityStateSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := decoded.toIdentityState()
	if len(got.tools) != 1 {
		t.Errorf("expected 1 tool after JSON round-trip, got %v", got.tools)
	}
	if !got.flaggedThisWindow[domain.KindMLScore] {
		t.Errorf("expected KindMLScore flagged after JSON round-trip, got %v", got.flaggedThisWindow)
	}
	if got.mlStats.rate.count != 1 {
		t.Errorf("expected mlStats.rate.count=1 after JSON round-trip, got %d", got.mlStats.rate.count)
	}
}
