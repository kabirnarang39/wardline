package domain

// Config is the per-job budget's own (yaml-free) configuration, mirroring
// taint/domain.Config's split from the platform config struct.
type Config struct {
	RequestsPerJob int // <=0 uses DefaultRequestsPerJob
}

const DefaultRequestsPerJob = 500

// Limit returns the configured per-job ceiling, or the default when unset.
func (c Config) Limit() int {
	if c.RequestsPerJob <= 0 {
		return DefaultRequestsPerJob
	}
	return c.RequestsPerJob
}
