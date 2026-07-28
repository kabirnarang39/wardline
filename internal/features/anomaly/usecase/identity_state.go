package usecase

import "time"

// windowCounts tracks total calls and deny-decision calls within one
// trailing window.
type windowCounts struct {
	total int
	deny  int
}

// identityState is one identity's rolling behavioral history: known
// tools (novel-tool heuristic, Task 4) and a current/previous pair of
// windowCounts (rate-spike's self-baseline and deny-rate-spike's ratio,
// both computed from the same trailing window -- see domain.HeuristicConfig).
// lastSeen drives GC eviction (Task 5).
type identityState struct {
	tools       map[string]struct{}
	windowStart time.Time
	cur         windowCounts
	prev        windowCounts
	lastSeen    time.Time
}
