package usecase_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
	"github.com/kabirnarang39/wardline/internal/features/costbudget/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/stretchr/testify/assert"
)

type fakeMeter struct {
	totals   map[string]int
	addCalls int // proves IsOverBudget never calls Add
	err      error
}

func newFakeMeter() *fakeMeter { return &fakeMeter{totals: map[string]int{}} }

func (m *fakeMeter) Add(key string, amount int, now time.Time) (int, error) {
	m.addCalls++
	if m.err != nil {
		return 0, m.err
	}
	m.totals[key] += amount
	return m.totals[key], nil
}

func (m *fakeMeter) Current(key string, now time.Time) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.totals[key], nil
}

func TestChecker_FlagOffAlwaysAllows(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{Ceiling: 1})
	v := c.Check("acme", "alice", "sess-1", "llm_call", time.Now())
	assert.True(t, v.Allowed)
}

func TestChecker_UnderCeilingAllows(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_cost_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{Ceiling: 100, ToolCosts: map[string]int{"llm_call": 30}})
	for i := 0; i < 3; i++ {
		v := c.Check("acme", "alice", "sess-1", "llm_call", time.Now())
		assert.True(t, v.Allowed, "call %d should be allowed", i+1)
	}
}

func TestChecker_OverCeilingDenies(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_cost_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{Ceiling: 50, ToolCosts: map[string]int{"llm_call": 30}})
	c.Check("acme", "alice", "sess-1", "llm_call", time.Now())
	v := c.Check("acme", "alice", "sess-1", "llm_call", time.Now()) // 60 > 50
	assert.False(t, v.Allowed)
	assert.Equal(t, 60, v.Total)
}

func TestChecker_JobsIsolatedByTenantIdentitySession(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_cost_budget": true})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{Ceiling: 20, ToolCosts: map[string]int{"llm_call": 20}})
	c.Check("acme", "alice", "sess-1", "llm_call", time.Now())
	v := c.Check("acme", "alice", "sess-2", "llm_call", time.Now()) // different session, own ceiling
	assert.True(t, v.Allowed)
}

func TestChecker_MeterErrorFailsOpen(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_cost_budget": true})
	m := newFakeMeter()
	m.err = fmt.Errorf("boom")
	c := usecase.NewChecker(f, m, domain.Config{Ceiling: 1})
	v := c.Check("acme", "alice", "sess-1", "llm_call", time.Now())
	assert.True(t, v.Allowed)
	assert.True(t, v.FailedOpen)
}

func TestChecker_IsOverBudgetReflectsPriorCallsOnlyNoAdd(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{"job_cost_budget": true})
	m := newFakeMeter()
	c := usecase.NewChecker(f, m, domain.Config{Ceiling: 50, ToolCosts: map[string]int{"llm_call": 60}})
	assert.False(t, c.IsOverBudget("acme", "alice", "sess-1", time.Now()))
	c.Check("acme", "alice", "sess-1", "llm_call", time.Now())
	assert.Equal(t, 1, m.addCalls)
	assert.True(t, c.IsOverBudget("acme", "alice", "sess-1", time.Now()))
	c.IsOverBudget("acme", "alice", "sess-1", time.Now())
	c.IsOverBudget("acme", "alice", "sess-1", time.Now())
	assert.Equal(t, 1, m.addCalls, "IsOverBudget must not call Add")
}

func TestChecker_IsOverBudgetFlagOffAlwaysFalse(t *testing.T) {
	f := flags.NewStaticProvider(map[string]bool{})
	c := usecase.NewChecker(f, newFakeMeter(), domain.Config{Ceiling: 1})
	assert.False(t, c.IsOverBudget("acme", "alice", "sess-1", time.Now()))
}
