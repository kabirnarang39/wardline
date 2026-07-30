package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/domain"
	"github.com/kabirnarang39/wardline/internal/features/budget/usecase"
)

type stubFlags struct {
	enabled bool
}

func (s stubFlags) Enabled(name string) bool { return s.enabled }

type alwaysDenyLimiter struct{}

func (alwaysDenyLimiter) Allow(identity, tenant string, now time.Time) domain.Verdict {
	return domain.Verdict{Allowed: false, Reason: "always denies"}
}

func TestChecker_FlagOffAlwaysAllows(t *testing.T) {
	c := usecase.NewChecker(stubFlags{enabled: false}, alwaysDenyLimiter{})
	got := c.Check("agent-abc123", "acme", time.Now())
	if !got.Allowed {
		t.Errorf("expected allowed when flag is off, even with a deny-everything limiter, got %+v", got)
	}
}

type recordingLimiter struct {
	calledWith       string
	calledWithTenant string
	verdict          domain.Verdict
}

func (r *recordingLimiter) Allow(identity, tenant string, now time.Time) domain.Verdict {
	r.calledWith = identity
	r.calledWithTenant = tenant
	return r.verdict
}

func TestChecker_FlagOnDelegatesToLimiter(t *testing.T) {
	limiter := &recordingLimiter{verdict: domain.Verdict{Allowed: false, Reason: "over budget"}}
	c := usecase.NewChecker(stubFlags{enabled: true}, limiter)
	got := c.Check("agent-abc123", "acme", time.Now())
	if got.Allowed {
		t.Error("expected the limiter's verdict (deny) to be used when flag is on")
	}
	if limiter.calledWith != "agent-abc123" {
		t.Errorf("expected limiter to be called with the identity, got %q", limiter.calledWith)
	}
	if limiter.calledWithTenant != "acme" {
		t.Errorf("expected limiter to be called with the tenant, got %q", limiter.calledWithTenant)
	}
}
