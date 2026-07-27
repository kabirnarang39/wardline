package usecase

import (
	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
)

// rbacFeatureFlag is the flags.Provider key that turns RBAC enforcement
// on. Off by default — a Checker built around a disabled flag never
// consults the authorizer at all.
const rbacFeatureFlag = "rbac"

// Checker gates a domain.Authorizer behind a feature flag: when the flag
// is off, every check passes regardless of what the authorizer would say.
type Checker struct {
	flags      flags.Provider
	authorizer domain.Authorizer
}

func NewChecker(f flags.Provider, authorizer domain.Authorizer) *Checker {
	return &Checker{flags: f, authorizer: authorizer}
}

func (c *Checker) Check(identity, tenant string, perm domain.Permission) bool {
	if !c.flags.Enabled(rbacFeatureFlag) {
		return true
	}
	return c.authorizer.Authorize(identity, tenant, perm)
}
