package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// IdentityStateSnapshot is identityState's JSON-serializable wire shape,
// stored one row per (tenant, identity) key by PostgresBaselineStore
// (internal/features/anomaly/adapter/postgres_baseline_store.go).
// Deliberately a separate exported type rather than exporting
// identityState's own fields directly: identityState stays free to
// evolve internally without dragging a persisted-JSON-shape
// compatibility burden along with every field rename. snapshotIdentityState
// and toIdentityState are the only two functions that ever convert
// between the two shapes.
type IdentityStateSnapshot struct {
	Tools             []string               `json:"tools"`
	WindowStart       time.Time              `json:"window_start"`
	Cur               WindowCountsSnapshot   `json:"cur"`
	Prev              WindowCountsSnapshot   `json:"prev"`
	FlaggedThisWindow []string               `json:"flagged_this_window"`
	LastSeen          time.Time              `json:"last_seen"`
	MLStats           MLFeatureStateSnapshot `json:"ml_stats"`
	LastCallAt        time.Time              `json:"last_call_at"`
}

// WindowCountsSnapshot mirrors windowCounts (identity_state.go).
// InterArrivalSum is stored as whole nanoseconds (time.Duration's own
// underlying type) rather than a formatted string -- exact, no parsing
// ambiguity, and JSON numbers losslessly represent an int64 nanosecond
// count for any duration this feature will ever see.
type WindowCountsSnapshot struct {
	Total           int      `json:"total"`
	ToolCalls       int      `json:"tool_calls"`
	Deny            int      `json:"deny"`
	UniqueTools     []string `json:"unique_tools"`
	InterArrivalSum int64    `json:"inter_arrival_sum_ns"`
	InterArrivalN   int      `json:"inter_arrival_n"`
}

// OnlineStatSnapshot mirrors onlineStat's three fields exactly
// (online_stat.go) -- mean/m2/count are Welford's algorithm's entire
// state, nothing else to persist.
type OnlineStatSnapshot struct {
	Mean  float64 `json:"mean"`
	M2    float64 `json:"m2"`
	Count int64   `json:"count"`
}

// MLFeatureStateSnapshot mirrors mlFeatureState's five onlineStat fields
// (identity_state.go).
type MLFeatureStateSnapshot struct {
	Rate         OnlineStatSnapshot `json:"rate"`
	Diversity    OnlineStatSnapshot `json:"diversity"`
	DenyRatio    OnlineStatSnapshot `json:"deny_ratio"`
	InterArrival OnlineStatSnapshot `json:"inter_arrival"`
	ToolCalls    OnlineStatSnapshot `json:"tool_calls"`
}

func stringSetToSlice(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sliceToStringSet(s []string) map[string]struct{} {
	if len(s) == 0 {
		return make(map[string]struct{})
	}
	out := make(map[string]struct{}, len(s))
	for _, k := range s {
		out[k] = struct{}{}
	}
	return out
}

func snapshotWindowCounts(w windowCounts) WindowCountsSnapshot {
	return WindowCountsSnapshot{
		Total:           w.total,
		ToolCalls:       w.toolCalls,
		Deny:            w.deny,
		UniqueTools:     stringSetToSlice(w.uniqueTools),
		InterArrivalSum: int64(w.interArrivalSum),
		InterArrivalN:   w.interArrivalN,
	}
}

func (s WindowCountsSnapshot) toWindowCounts() windowCounts {
	return windowCounts{
		total:           s.Total,
		toolCalls:       s.ToolCalls,
		deny:            s.Deny,
		uniqueTools:     sliceToStringSet(s.UniqueTools),
		interArrivalSum: time.Duration(s.InterArrivalSum),
		interArrivalN:   s.InterArrivalN,
	}
}

func snapshotOnlineStat(s onlineStat) OnlineStatSnapshot {
	return OnlineStatSnapshot{Mean: s.mean, M2: s.m2, Count: s.count}
}

func (s OnlineStatSnapshot) toOnlineStat() onlineStat {
	return onlineStat{mean: s.Mean, m2: s.M2, count: s.Count}
}

func snapshotMLFeatureState(m mlFeatureState) MLFeatureStateSnapshot {
	return MLFeatureStateSnapshot{
		Rate:         snapshotOnlineStat(m.rate),
		Diversity:    snapshotOnlineStat(m.diversity),
		DenyRatio:    snapshotOnlineStat(m.denyRatio),
		InterArrival: snapshotOnlineStat(m.interArrival),
		ToolCalls:    snapshotOnlineStat(m.toolCalls),
	}
}

func (s MLFeatureStateSnapshot) toMLFeatureState() mlFeatureState {
	return mlFeatureState{
		rate:         s.Rate.toOnlineStat(),
		diversity:    s.Diversity.toOnlineStat(),
		denyRatio:    s.DenyRatio.toOnlineStat(),
		interArrival: s.InterArrival.toOnlineStat(),
		toolCalls:    s.ToolCalls.toOnlineStat(),
	}
}

// snapshotIdentityState converts a live identityState into its
// persisted-JSON shape. Called under Detector.mu (see gc.go's Task 3
// usage) -- st must not be concurrently mutated while this runs.
func snapshotIdentityState(st *identityState) IdentityStateSnapshot {
	flagged := make([]string, 0, len(st.flaggedThisWindow))
	for k, v := range st.flaggedThisWindow {
		if v {
			flagged = append(flagged, string(k))
		}
	}
	return IdentityStateSnapshot{
		Tools:             stringSetToSlice(st.tools),
		WindowStart:       st.windowStart,
		Cur:               snapshotWindowCounts(st.cur),
		Prev:              snapshotWindowCounts(st.prev),
		FlaggedThisWindow: flagged,
		LastSeen:          st.lastSeen,
		MLStats:           snapshotMLFeatureState(st.mlStats),
		LastCallAt:        st.lastCallAt,
	}
}

// toIdentityState converts a persisted snapshot back into a live
// identityState -- the inverse of snapshotIdentityState. Used only at
// startup (Task 3's load path); never on the request path.
func (s IdentityStateSnapshot) toIdentityState() *identityState {
	var flagged map[domain.Kind]bool
	if len(s.FlaggedThisWindow) > 0 {
		flagged = make(map[domain.Kind]bool, len(s.FlaggedThisWindow))
		for _, k := range s.FlaggedThisWindow {
			flagged[domain.Kind(k)] = true
		}
	}
	return &identityState{
		tools:             sliceToStringSet(s.Tools),
		windowStart:       s.WindowStart,
		cur:               s.Cur.toWindowCounts(),
		prev:              s.Prev.toWindowCounts(),
		flaggedThisWindow: flagged,
		lastSeen:          s.LastSeen,
		mlStats:           s.MLStats.toMLFeatureState(),
		lastCallAt:        s.LastCallAt,
	}
}
