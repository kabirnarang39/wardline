package domain

// Config is the per-job budget's own (yaml-free) configuration, mirroring
// taint/domain.Config's split from the platform config struct.
type Config struct {
	RequestsPerJob int // <=0 uses DefaultRequestsPerJob

	// SessionWindowSeconds is the sliding-window width for the fallback
	// session id used when no session header is present -- mirrors
	// taint/domain.TaintConfig.SessionWindowSeconds exactly, own knob
	// rather than a shared one so job-budget's window stays configurable
	// independently of taint_tracking being on. <=0 uses
	// DefaultSessionWindowSeconds.
	SessionWindowSeconds int
}

const DefaultRequestsPerJob = 500
const DefaultSessionWindowSeconds = 300

// Limit returns the configured per-job ceiling, or the default when unset.
func (c Config) Limit() int {
	if c.RequestsPerJob <= 0 {
		return DefaultRequestsPerJob
	}
	return c.RequestsPerJob
}

// Window returns the configured session-window width in seconds, or the
// default when unset.
func (c Config) Window() int {
	if c.SessionWindowSeconds <= 0 {
		return DefaultSessionWindowSeconds
	}
	return c.SessionWindowSeconds
}
