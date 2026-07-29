package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// windowCounts tracks one identity's traffic within one trailing window.
// total counts every audit entry (including MCP protocol-lifecycle
// passthrough), because rate-spike is a volumetric signal over all of an
// identity's traffic. toolCalls counts only policy-evaluated tool calls
// and is deny-rate-spike's denominator -- see isToolCall in detector.go
// for why protocol chatter must not dilute that ratio.
//
// uniqueTools, interArrivalSum, and interArrivalN exist only for
// ml_score's per-window features: uniqueTools is this window's distinct
// tool set (reset every window, unlike identityState.tools which is
// all-time -- ml_score cares about *this window's* diversity, not
// whether a tool has ever been seen before). interArrivalSum/N accumulate
// the deltas between consecutive calls this window so their mean (a
// window-level "how bursty was this window" feature) can be computed once
// the window is over.
type windowCounts struct {
	total     int
	toolCalls int
	deny      int

	uniqueTools     map[string]struct{} // per-window distinct tool set, for ml_score's diversity feature
	interArrivalSum time.Duration       // sum of deltas between consecutive calls this window
	interArrivalN   int                 // count of deltas summed (total-1 within-window calls, at most)
}

// mlFeatureState holds ml_score's four persistent per-identity running
// baselines. Unlike windowCounts (reset every window), these accumulate
// across every window for the identity's whole lifetime (until GC drops
// the identity) -- they ARE the baseline windowCounts is compared
// against.
type mlFeatureState struct {
	rate         onlineStat
	diversity    onlineStat
	denyRatio    onlineStat
	interArrival onlineStat
}

// identityState is one identity's rolling behavioral history: known
// tools (novel-tool heuristic, Task 4) and a current/previous pair of
// windowCounts (rate-spike's self-baseline and deny-rate-spike's ratio,
// both computed from the same trailing window -- see domain.HeuristicConfig).
// flaggedThisWindow latches which heuristic Kinds have already fired for
// the current window, so a sustained spike emits one Anomaly per window
// rather than one per call; it's cleared whenever the window rotates.
// lastSeen drives GC eviction (Task 5). mlStats is ml_score's persistent
// running baseline (never reset on rollover -- see mlFeatureState).
// lastCallAt persists across window rollovers too, so the very first
// inter-arrival delta of a new window is measured against the last call
// of the previous window rather than being undefined -- a deliberate
// simplification, not a bug (see the design doc's Testing section).
type identityState struct {
	tools             map[string]struct{}
	windowStart       time.Time
	cur               windowCounts
	prev              windowCounts
	flaggedThisWindow map[domain.Kind]bool
	lastSeen          time.Time
	mlStats           mlFeatureState
	lastCallAt        time.Time
}
