package domain

import "time"

// Verdict is the result of checking whether an identity may proceed under
// the current budget.
type Verdict struct {
	Allowed bool
	Reason  string

	// RetryAfter is how long until the caller's window resets. Only
	// meaningful when Allowed is false — never read otherwise.
	RetryAfter time.Duration
}

// Limiter decides whether an identity may make another call right now.
type Limiter interface {
	Allow(identity string, now time.Time) Verdict
}
