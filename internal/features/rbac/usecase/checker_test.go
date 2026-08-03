package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

type stubFlags struct {
	enabled bool
}

func (s stubFlags) Enabled(name string) bool { return s.enabled }

type denyAllAuthorizer struct{}

func (denyAllAuthorizer) Authorize(identity, tenant string, perm domain.Permission) bool {
	return false
}

func (denyAllAuthorizer) IsGlobal(identity string, perm domain.Permission) bool {
	return false
}

func TestChecker_FlagOffAlwaysAllows(t *testing.T) {
	c := usecase.NewChecker(stubFlags{enabled: false}, denyAllAuthorizer{})
	if !c.Check("alice", "default", domain.PermissionDashboardView) {
		t.Error("expected allowed when flag is off, even with a deny-everything authorizer")
	}
}

type recordingAuthorizer struct {
	identity, tenant string
	perm             domain.Permission
	verdict          bool
}

func (r *recordingAuthorizer) Authorize(identity, tenant string, perm domain.Permission) bool {
	r.identity, r.tenant, r.perm = identity, tenant, perm
	return r.verdict
}

func (r *recordingAuthorizer) IsGlobal(identity string, perm domain.Permission) bool {
	return r.verdict
}

func TestChecker_FlagOnDelegatesToAuthorizer(t *testing.T) {
	authorizer := &recordingAuthorizer{verdict: false}
	c := usecase.NewChecker(stubFlags{enabled: true}, authorizer)
	got := c.Check("alice", "default", domain.PermissionDashboardView)
	if got {
		t.Error("expected the authorizer's verdict (deny) to be used when flag is on")
	}
	if authorizer.identity != "alice" || authorizer.tenant != "default" || authorizer.perm != domain.PermissionDashboardView {
		t.Errorf("expected authorizer called with (alice, default, dashboard:view), got (%q, %q, %q)", authorizer.identity, authorizer.tenant, authorizer.perm)
	}
}

// TestChecker_IsGlobal_FlagOffAlwaysAllows mirrors
// TestChecker_FlagOffAlwaysAllows: IsGlobal takes the same flag-gated
// "flag off means always true" posture as Check, even with an authorizer
// that would otherwise say no ClusterRoleBinding applies.
func TestChecker_IsGlobal_FlagOffAlwaysAllows(t *testing.T) {
	c := usecase.NewChecker(stubFlags{enabled: false}, denyAllAuthorizer{})
	if !c.IsGlobal("alice", domain.PermissionCredentialRevoke) {
		t.Error("expected IsGlobal to return true when the flag is off, even with a deny-everything authorizer")
	}
}

// TestChecker_IsGlobal_FlagOnDelegatesToAuthorizer mirrors
// TestChecker_FlagOnDelegatesToAuthorizer for the IsGlobal path.
func TestChecker_IsGlobal_FlagOnDelegatesToAuthorizer(t *testing.T) {
	authorizer := &recordingAuthorizer{verdict: true}
	c := usecase.NewChecker(stubFlags{enabled: true}, authorizer)
	if !c.IsGlobal("alice", domain.PermissionCredentialRevoke) {
		t.Error("expected the authorizer's verdict (allow) to be used when flag is on")
	}
}

// TestChecker_ReloadTakesEffectOnNextCall proves the core hot-reload
// guarantee for RBAC: swapping the authorizer behind a Checker's
// ReloadableEngine holder is observed by that SAME Checker instance on
// its very next Check call -- no new Checker, no restart. Mirrors
// proxy/usecase's TestDecider_ReloadTakesEffectOnNextCall.
func TestChecker_ReloadTakesEffectOnNextCall(t *testing.T) {
	var authorizer domain.Authorizer = denyAllAuthorizer{}
	holder := reload.NewReloadableEngine(&authorizer)

	c := usecase.NewCheckerWithHolder(stubFlags{enabled: true}, holder)

	if c.Check("alice", "default", domain.PermissionDashboardView) {
		t.Fatal("before reload: expected denied (denyAllAuthorizer), got allowed")
	}

	var newAuthorizer domain.Authorizer = &recordingAuthorizer{verdict: true}
	holder.Swap(&newAuthorizer)

	// Same Checker instance, very next call, no restart.
	if !c.Check("alice", "default", domain.PermissionDashboardView) {
		t.Fatal("after reload: expected allowed -- Checker is not reading through the ReloadableEngine on every call")
	}
}

// TestChecker_IsGlobal_ReloadTakesEffectOnNextCall mirrors
// TestChecker_ReloadTakesEffectOnNextCall for the IsGlobal path.
func TestChecker_IsGlobal_ReloadTakesEffectOnNextCall(t *testing.T) {
	var authorizer domain.Authorizer = denyAllAuthorizer{}
	holder := reload.NewReloadableEngine(&authorizer)

	c := usecase.NewCheckerWithHolder(stubFlags{enabled: true}, holder)

	if c.IsGlobal("alice", domain.PermissionCredentialRevoke) {
		t.Fatal("before reload: expected denied (denyAllAuthorizer), got allowed")
	}

	var newAuthorizer domain.Authorizer = &recordingAuthorizer{verdict: true}
	holder.Swap(&newAuthorizer)

	if !c.IsGlobal("alice", domain.PermissionCredentialRevoke) {
		t.Fatal("after reload: expected allowed -- Checker.IsGlobal is not reading through the ReloadableEngine on every call")
	}
}
