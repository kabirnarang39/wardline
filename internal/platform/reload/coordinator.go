package reload

import "time"

// ReloadResult records the outcome of a single reload attempt -- both a
// return value for the HTTP caller and the payload OnAudit receives.
type ReloadResult struct {
	Domain    string
	OK        bool
	Error     string
	AppliedBy string
	Timestamp time.Time
}

// ReloadCoordinator dispatches a reload request to the named domain's
// registered closure and unconditionally reports the outcome via
// OnAudit -- a rejected reload is exactly as important to surface as an
// accepted one, so OnAudit fires on both paths, never only on success.
type ReloadCoordinator struct {
	Reloaders map[string]func() error
	OnAudit   func(ReloadResult)
}

// Reload looks up domain in c.Reloaders and invokes it, reporting the
// outcome via c.OnAudit before returning -- an unknown domain is itself
// a rejected attempt (Error = "unknown domain") and is audited the same
// as any other failure.
func (c *ReloadCoordinator) Reload(domain, appliedBy string) ReloadResult {
	fn, ok := c.Reloaders[domain]
	result := ReloadResult{Domain: domain, AppliedBy: appliedBy, Timestamp: time.Now()}
	if !ok {
		result.Error = "unknown domain"
		c.OnAudit(result)
		return result
	}
	if err := fn(); err != nil {
		result.Error = err.Error()
	} else {
		result.OK = true
	}
	c.OnAudit(result)
	return result
}
