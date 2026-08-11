package usecase_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	"github.com/kabirnarang39/wardline/internal/features/jobbudget/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/stretchr/testify/assert"
)

type fakeMeter struct {
	counts         map[string]int
	incrementCalls int // how many times Increment was called, total -- proves IsOverBudget never increments
	err            error
}

func newFakeMeter() *fakeMeter { return &fakeMeter{counts: map[string]int{}} }

func (m *fakeMeter) Increment(key string, now time.Time) (int, error) {
	m.incrementCalls++
	if m.err != nil {
		return 0, m.err
	}
	m.counts[key]++
	return m.counts[key], nil
}

func (m *fakeMeter) Current(key string, now time.Time) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.counts[key], nil
}

func TestChecker_FlagOffAlwaysAllows(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{}) // job_budget absent -> off
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{RequestsPerJob: 1})
	v := c.Check("acme", "alice", "sess-1", time.Now())
	assert.True(t, v.Allowed)
}

func TestChecker_UnderCeilingAllows(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{RequestsPerJob: 3})
	for i := 0; i < 3; i++ {
		v := c.Check("acme", "alice", "sess-1", time.Now())
		assert.True(t, v.Allowed, "call %d should be allowed", i+1)
	}
}

func TestChecker_OverCeilingDenies(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{RequestsPerJob: 2})
	c.Check("acme", "alice", "sess-1", time.Now())
	c.Check("acme", "alice", "sess-1", time.Now())
	v := c.Check("acme", "alice", "sess-1", time.Now())
	assert.False(t, v.Allowed)
	assert.Equal(t, 3, v.Count)
}

func TestChecker_JobsIsolatedByTenantIdentitySession(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{RequestsPerJob: 1})
	c.Check("acme", "alice", "sess-1", time.Now())
	v := c.Check("acme", "alice", "sess-2", time.Now()) // different session, own ceiling
	assert.True(t, v.Allowed)
}

func TestChecker_MeterErrorFailsOpen(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_budget": true})
	m := newFakeMeter()
	m.err = fmt.Errorf("boom")
	c := usecase.NewChecker(f, m, domain.Config{RequestsPerJob: 1})
	v := c.Check("acme", "alice", "sess-1", time.Now())
	assert.True(t, v.Allowed)
	assert.True(t, v.FailedOpen)
}

func TestChecker_IsOverBudgetReflectsPriorCallsOnlyNoIncrement(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_budget": true})
	m := newFakeMeter()
	c := usecase.NewChecker(f, m, domain.Config{RequestsPerJob: 1})
	// No calls yet -> not over budget.
	assert.False(t, c.IsOverBudget("acme", "alice", "sess-1", time.Now()))
	// One incrementing Check reaches the ceiling.
	c.Check("acme", "alice", "sess-1", time.Now())
	assert.Equal(t, 1, m.incrementCalls)
	assert.True(t, c.IsOverBudget("acme", "alice", "sess-1", time.Now()))
	// IsOverBudget itself must never increment -- calling it repeatedly
	// must not change the underlying count.
	c.IsOverBudget("acme", "alice", "sess-1", time.Now())
	c.IsOverBudget("acme", "alice", "sess-1", time.Now())
	assert.Equal(t, 1, m.incrementCalls, "IsOverBudget must not call Increment")
}

func TestChecker_IsOverBudgetFlagOffAlwaysFalse(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{RequestsPerJob: 1})
	assert.False(t, c.IsOverBudget("acme", "alice", "sess-1", time.Now()))
}

// TestChecker_NoSessionHeaderFallsBackToTTLWindow proves a job with no
// explicit session (the empty string a missing X-Wardline-Session header
// produces) still shares one ceiling across calls within the same
// session-window bucket -- the same TTL-fallback platformsession.SessionID
// gives taint tracking, now applied here too. Without this, every
// no-header call would key off a literal "" session and never roll over.
func TestChecker_NoSessionHeaderFallsBackToTTLWindow(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{RequestsPerJob: 2, SessionWindowSeconds: 300})
	base := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

	c.Check("acme", "alice", "", base)
	v := c.Check("acme", "alice", "", base.Add(100*time.Second)) // same window
	assert.Equal(t, 2, v.Count)

	// Next window bucket -- a fresh ceiling, same as taint's own rollover.
	v = c.Check("acme", "alice", "", base.Add(400*time.Second))
	assert.True(t, v.Allowed)
	assert.Equal(t, 1, v.Count)
}
