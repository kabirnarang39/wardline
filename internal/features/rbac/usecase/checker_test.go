package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
)

type stubFlags struct {
	enabled bool
}

func (s stubFlags) Enabled(name string) bool { return s.enabled }

type denyAllAuthorizer struct{}

func (denyAllAuthorizer) Authorize(identity, tenant string, perm domain.Permission) bool {
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
