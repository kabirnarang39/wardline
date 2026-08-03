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

func (alwaysDenyLimiter) Allow(identity, tenant, tool string, now time.Time) domain.Verdict {
	return domain.Verdict{Allowed: false, Reason: "always denies"}
}

// The methods below are no-op stubs satisfying domain.Limiter's
// hot-reload setter/clear methods -- this fake only exercises Allow, not
// reload behavior (see the InMemoryLimiter/PostgresLimiter tests for that).
func (alwaysDenyLimiter) SetDefaultLimit(requestsPerWindow int, window time.Duration) {}
func (alwaysDenyLimiter) SetTenantLimit(tenantName string, requestsPerWindow int, window time.Duration) {
}
func (alwaysDenyLimiter) ClearTenantLimit(tenantName string) {}
func (alwaysDenyLimiter) SetToolLimit(toolName string, requestsPerWindow int, window time.Duration) {
}
func (alwaysDenyLimiter) ClearToolLimit(toolName string) {}

func TestChecker_FlagOffAlwaysAllows(t *testing.T) {
	c := usecase.NewChecker(stubFlags{enabled: false}, alwaysDenyLimiter{})
	got := c.Check("agent-abc123", "acme", "some_tool", time.Now())
	if !got.Allowed {
		t.Errorf("expected allowed when flag is off, even with a deny-everything limiter, got %+v", got)
	}
}

type recordingLimiter struct {
	calledWith       string
	calledWithTenant string
	calledWithTool   string
	verdict          domain.Verdict
}

func (r *recordingLimiter) Allow(identity, tenant, tool string, now time.Time) domain.Verdict {
	r.calledWith = identity
	r.calledWithTenant = tenant
	r.calledWithTool = tool
	return r.verdict
}

// No-op stubs, same rationale as alwaysDenyLimiter's above.
func (r *recordingLimiter) SetDefaultLimit(requestsPerWindow int, window time.Duration) {}
func (r *recordingLimiter) SetTenantLimit(tenantName string, requestsPerWindow int, window time.Duration) {
}
func (r *recordingLimiter) ClearTenantLimit(tenantName string) {}
func (r *recordingLimiter) SetToolLimit(toolName string, requestsPerWindow int, window time.Duration) {
}
func (r *recordingLimiter) ClearToolLimit(toolName string) {}

func TestChecker_FlagOnDelegatesToLimiter(t *testing.T) {
	limiter := &recordingLimiter{verdict: domain.Verdict{Allowed: false, Reason: "over budget"}}
	c := usecase.NewChecker(stubFlags{enabled: true}, limiter)
	got := c.Check("agent-abc123", "acme", "some_tool", time.Now())
	if got.Allowed {
		t.Error("expected the limiter's verdict (deny) to be used when flag is on")
	}
	if limiter.calledWith != "agent-abc123" {
		t.Errorf("expected limiter to be called with the identity, got %q", limiter.calledWith)
	}
	if limiter.calledWithTenant != "acme" {
		t.Errorf("expected limiter to be called with the tenant, got %q", limiter.calledWithTenant)
	}
	if limiter.calledWithTool != "some_tool" {
		t.Errorf("expected limiter to be called with the tool, got %q", limiter.calledWithTool)
	}
}
