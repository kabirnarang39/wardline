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
	interArrivalN   int                 // count of deltas summed -- exactly total-1 within-window calls, since lastCallAt resets to zero on rollover (no cross-window delta)
}

// mlFeatureState holds ml_score's four scored features' persistent
// per-identity running baselines, plus a fifth, toolCalls, used only to
// gate deny_ratio's auto-block candidacy on whether ITS OWN denominator
// declined -- zRate (scored from windowCounts.total, deliberately
// inclusive of protocol passthrough) is not a valid proxy for this,
// since total can hold steady or rise while toolCalls -- deny_ratio's
// actual denominator -- collapses (a reconnect storm or a burst of
// tool-less error entries pads total without adding a single real tool
// call). toolCalls itself is never scored as an anomaly or logged in
// ml_score's Detail string; it exists solely to gate deny_ratio's block
// candidacy correctly. Unlike windowCounts (reset every window), these
// accumulate across every window for the identity's whole lifetime
// (until GC drops the identity) -- they ARE the baseline windowCounts is
// compared against.
type mlFeatureState struct {
	rate         onlineStat
	diversity    onlineStat
	denyRatio    onlineStat
	interArrival onlineStat
	toolCalls    onlineStat
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
// lastCallAt is reset to the zero value on every window rollover (see
// recordAndCheck), so the first call of a new window never contributes an
// inter-arrival delta measured against however long the identity happened
// to be idle across the boundary -- an identity that pauses and resumes
// must not have that idle gap read as a wild inter_arrival_time outlier.
type identityState struct {
	tools             map[string]struct{}
	windowStart       time.Time
	cur               windowCounts
	prev              windowCounts
	flaggedThisWindow map[domain.Kind]bool
	lastSeen          time.Time
	mlStats           mlFeatureState
	lastCallAt        time.Time

	// driftCUSUM is drift_detection's running one-sided CUSUM
	// accumulator over call_rate's standardized per-window deviation --
	// persistent across windows (unlike windowCounts), reset to 0 on any
	// below-allowance window and after every alarm (see checkDrift's doc
	// comment). Zero value is exactly a fresh CUSUM's own starting state,
	// so no separate "has this identity ever been scored" tracking is
	// needed the way mlStats.rate.count already provides for onlineStat.
	driftCUSUM float64
	// driftDiversityCUSUM is checkDrift's second, independent CUSUM
	// accumulator over tool_diversity -- same mechanics as driftCUSUM,
	// separate state because the two features' baselines (and thus
	// their z values) are unrelated (see checkDrift's doc comment).
	driftDiversityCUSUM float64
}
