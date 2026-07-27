package domain

// StatusInfo is a point-in-time snapshot of the running server, shown on
// the dashboard's Status view.
type StatusInfo struct {
	Version       string
	UptimeSeconds int64
	Listen        string
	Upstream      string
	Features      map[string]bool
}

// PolicyInfo is the active policy engine's backend name and raw source,
// captured once at startup — policy is not hot-reloaded, so this never
// changes for the life of the process.
type PolicyInfo struct {
	Backend string
	Source  string
}
