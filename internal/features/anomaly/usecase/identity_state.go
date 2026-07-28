package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

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
// flaggedThisWindow latches which heuristic Kinds have already fired for
// the current window, so a sustained spike emits one Anomaly per window
// rather than one per call; it's cleared whenever the window rotates.
// lastSeen drives GC eviction (Task 5).
type identityState struct {
	tools             map[string]struct{}
	windowStart       time.Time
	cur               windowCounts
	prev              windowCounts
	flaggedThisWindow map[domain.Kind]bool
	lastSeen          time.Time
}
