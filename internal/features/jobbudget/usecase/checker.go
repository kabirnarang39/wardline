package usecase

import (
	"fmt"
	"strconv"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	platformsession "github.com/kabirnarang39/wardline/internal/platform/session"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

const jobBudgetFeatureFlag = "job_budget"

// jobKey composes (tenant, identity, session) into one unambiguous key —
// the same length-prefixed anti-spoofing composition taint.taintKey and
// approval.grantKey use, so two tenants' identically-named identities or
// sessions never share a job ceiling. session is expected to already be
// resolved (explicit header value, or the TTL-window fallback bucket) —
// see Check/IsOverBudget, which apply platformsession.SessionID before
// calling this.
func jobKey(tenantName, identity, session string) string {
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

func (c *Checker) Check(tenantName, identity, session string, now time.Time) domain.Verdict {
	if !c.flags.Enabled(jobBudgetFeatureFlag) {
		return domain.Verdict{Allowed: true, Reason: "job budget disabled"}
	}
	session = platformsession.SessionID(session, tenantName, identity, now, c.cfg.Window())
	count, err := c.meter.Increment(jobKey(tenantName, identity, session), now)
	if err != nil {
		// Availability over enforcement on a genuine backend error — same
		// precedent as budget.Verdict.FailedOpen. Never silent: FailedOpen
		// lets the caller record a durable audit marker instead of just a
		// Warn log line.
		return domain.Verdict{Allowed: true, Reason: fmt.Sprintf("job budget check failed open: %v", err), FailedOpen: true}
	}
	limit := c.cfg.Limit()
	if count > limit {
		return domain.Verdict{Allowed: false, Reason: fmt.Sprintf("job budget ceiling %d reached", limit), Count: count}
	}
	return domain.Verdict{Allowed: true, Count: count}
}

// IsOverBudget is a non-incrementing peek: has this job already exceeded
// its ceiling based on PRIOR calls (never this one)? Used by the policy
// decision path, which must not have a side effect -- Check (above) is
// the only method that increments, called exactly once per request by
// the proxy handler's hard gate. A meter error or the flag being off both
// resolve to false: this is a read used to grant a policy extra power
// (routing to approval), never to take power away, so it fails toward
// "don't know, assume not over" rather than a false positive.
func (c *Checker) IsOverBudget(tenantName, identity, session string, now time.Time) bool {
	if !c.flags.Enabled(jobBudgetFeatureFlag) {
		return false
	}
	session = platformsession.SessionID(session, tenantName, identity, now, c.cfg.Window())
	count, err := c.meter.Current(jobKey(tenantName, identity, session), now)
	if err != nil {
		return false
	}
	return count >= c.cfg.Limit()
}
