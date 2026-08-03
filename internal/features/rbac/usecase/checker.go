package usecase

import (
	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

// rbacFeatureFlag is the flags.Provider key that turns RBAC enforcement
// on. Off by default — a Checker built around a disabled flag never
// consults the authorizer at all.
const rbacFeatureFlag = "rbac"

// Checker gates a domain.Authorizer behind a feature flag: when the flag
// is off, every check passes regardless of what the authorizer would say.
// The authorizer is held behind a ReloadableEngine so a hot reload (see
// main.go's rbac reload closure) takes effect on this same Checker
// instance's very next Check/IsGlobal call, with no restart -- same
// pattern as proxy/usecase.Decider.
type Checker struct {
	flags      flags.Provider
	authorizer *reload.ReloadableEngine[domain.Authorizer]
}

// NewChecker wraps authorizer in a fresh, private ReloadableEngine holder
// -- callers that don't care about reload (most existing tests and call
// sites) keep working unchanged. Use NewCheckerWithHolder when the
// caller needs to reload the authorizer later via the same holder.
func NewChecker(f flags.Provider, authorizer domain.Authorizer) *Checker {
	return &Checker{flags: f, authorizer: reload.NewReloadableEngine(&authorizer)}
}

// NewCheckerWithHolder builds a Checker backed by an existing
// ReloadableEngine holder, so a later Swap on that holder (e.g. from the
// rbac hot-reload path in main.go) is observed by this Checker on its
// very next Check/IsGlobal call.
func NewCheckerWithHolder(f flags.Provider, holder *reload.ReloadableEngine[domain.Authorizer]) *Checker {
	return &Checker{flags: f, authorizer: holder}
}

func (c *Checker) Check(identity, tenant string, perm domain.Permission) bool {
	if !c.flags.Enabled(rbacFeatureFlag) {
		return true
	}
	authorizer := *c.authorizer.Current()
	return authorizer.Authorize(identity, tenant, perm)
}

// IsGlobal reports whether identity holds perm via a ClusterRoleBinding
// (every tenant), same flag-gated posture as Check: flag off means every
// caller is treated as globally granted, matching Check's "always allow".
func (c *Checker) IsGlobal(identity string, perm domain.Permission) bool {
	if !c.flags.Enabled(rbacFeatureFlag) {
		return true
	}
	authorizer := *c.authorizer.Current()
	return authorizer.IsGlobal(identity, perm)
}
