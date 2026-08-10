package usecase

import (
	"fmt"
	"strconv"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

const costBudgetFeatureFlag = "job_cost_budget"

// costKey composes (tenant, identity, session) into one unambiguous key --
// the same length-prefixed anti-spoofing composition jobbudget.jobKey,
// taint.taintKey, and approval.grantKey all use. costbudget's counters
// live in their own map/table (never shared with jobbudget's), so this
// key never collides with a jobbudget key even though the composition is
// identical -- the two features never read/write the same store.
func costKey(tenantName, identity, session string) string {
	base := tenant.Key(tenantName, identity)
	return strconv.Itoa(len(base)) + ":" + base + session
}

// Checker gates a domain.Meter behind a feature flag: when the flag is
// off, every call is allowed and the meter is never touched.
type Checker struct {
	flags flags.Provider
	meter domain.Meter
	cfg   domain.Config
}

func NewChecker(f flags.Provider, meter domain.Meter, cfg domain.Config) *Checker {
	return &Checker{flags: f, meter: meter, cfg: cfg}
}

func (c *Checker) Check(tenantName, identity, session, tool string, now time.Time) domain.Verdict {
	if !c.flags.Enabled(costBudgetFeatureFlag) {
		return domain.Verdict{Allowed: true, Reason: "cost budget disabled"}
	}
	amount := c.cfg.CostOf(tool)
	total, err := c.meter.Add(costKey(tenantName, identity, session), amount, now)
	if err != nil {
		return domain.Verdict{Allowed: true, Reason: fmt.Sprintf("cost budget check failed open: %v", err), FailedOpen: true}
	}
	limit := c.cfg.Limit()
	if total > limit {
		return domain.Verdict{Allowed: false, Reason: fmt.Sprintf("cost budget ceiling %d reached", limit), Total: total}
	}
	return domain.Verdict{Allowed: true, Total: total}
}

// IsOverBudget is a non-incrementing peek: has this job already exceeded
// its cost ceiling based on PRIOR calls (never this one)? Mirrors
// jobbudget.Checker.IsOverBudget exactly -- see that method's doc comment
// for the full rationale (Check is the only method with a side effect,
// called exactly once per request by the proxy handler's hard gate).
func (c *Checker) IsOverBudget(tenantName, identity, session string, now time.Time) bool {
	if !c.flags.Enabled(costBudgetFeatureFlag) {
		return false
	}
	total, err := c.meter.Current(costKey(tenantName, identity, session), now)
	if err != nil {
		return false
	}
	return total >= c.cfg.Limit()
}
