package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/domain"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
)

// budgetFeatureFlag is the flags.Provider key that turns budget enforcement
// on. Off by default — a Checker built around a disabled flag never
// consults the limiter at all, so an operator who hasn't opted in pays no
// cost and sees no behavior change.
const budgetFeatureFlag = "budget_enforcement"

// Checker gates a domain.Limiter behind a feature flag: when the flag is
// off, every call is allowed regardless of what the limiter would say.
type Checker struct {
	flags   flags.Provider
	limiter domain.Limiter
}

func NewChecker(f flags.Provider, limiter domain.Limiter) *Checker {
	return &Checker{flags: f, limiter: limiter}
}

func (c *Checker) Check(identity, tenant string, now time.Time) domain.Verdict {
	if !c.flags.Enabled(budgetFeatureFlag) {
		// RetryAfter is unused when Allowed is true; zero explicitly for
		// consistency with the deny path's struct construction.
		return domain.Verdict{Allowed: true, Reason: "budget enforcement disabled", RetryAfter: 0}
	}
	return c.limiter.Allow(identity, tenant, now)
}
