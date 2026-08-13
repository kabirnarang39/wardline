package usecase

import (
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

// TaintLookup reports a call's (tenant, identity, session) taint state.
// Supplied only when taint_tracking is on; a nil lookup means untainted (the
// zero domain.TaintSignal), so the feature adds zero behavior when off.
type TaintLookup func(domain.ToolCall) domain.TaintSignal

// JobBudgetLookup reports whether a call's (tenant, identity, session) job
// has exceeded its per-job request ceiling. Supplied only when job_budget is
// on; a nil lookup means within budget, so the feature adds zero behavior
// when off.
type JobBudgetLookup func(domain.ToolCall) bool

// CostBudgetLookup reports whether a call's (tenant, identity, session) job
// has exceeded its per-job cost/token ceiling. Supplied only when job_cost_budget
// is on; a nil lookup means within budget, so the feature adds zero behavior
// when off.
type CostBudgetLookup func(domain.ToolCall) bool

// Decider evaluates a ToolCall against the policy engine and returns
// whether the call may proceed. The engine is held behind a
// ReloadableEngine so a hot reload takes effect on the very next Decide
// call, on this same Decider instance, with no restart.
type Decider struct {
	policy     *reload.ReloadableEngine[policydomain.Engine]
	taint      TaintLookup
	jobBudget  JobBudgetLookup
	costBudget CostBudgetLookup
}

// NewDecider wraps policy in a fresh, private ReloadableEngine holder --
// callers that don't care about reload (most existing tests and
// call sites) keep working unchanged. Use NewDeciderWithHolder when the
// caller needs to reload the engine later via the same holder.
func NewDecider(policy policydomain.Engine) *Decider {
	return &Decider{policy: reload.NewReloadableEngine(&policy)}
}

// NewDeciderWithHolder builds a Decider backed by an existing
// ReloadableEngine holder, so a later Swap on that holder (e.g. from the
// policy hot-reload path in main.go) is observed by this Decider on its
// very next Decide call.
func NewDeciderWithHolder(holder *reload.ReloadableEngine[policydomain.Engine]) *Decider {
	return &Decider{policy: holder}
}

// NewDeciderWithHolderAndTaint is NewDeciderWithHolder plus a taint lookup
// consulted at decision time, wired only when taint_tracking is on. A nil
// taint lookup is equivalent to NewDeciderWithHolder.
func NewDeciderWithHolderAndTaint(holder *reload.ReloadableEngine[policydomain.Engine], taint TaintLookup) *Decider {
	return &Decider{policy: holder, taint: taint}
}

// NewDeciderWithHolderTaintAndJobBudget is NewDeciderWithHolder plus both a
// taint lookup and a job-budget lookup, each consulted at decision time. A nil
// lookup means the feature is off for that dimension (untainted or within
// budget, respectively), so the feature adds zero behavior when both are nil.
func NewDeciderWithHolderTaintAndJobBudget(holder *reload.ReloadableEngine[policydomain.Engine], taint TaintLookup, jobBudget JobBudgetLookup) *Decider {
	return &Decider{policy: holder, taint: taint, jobBudget: jobBudget}
}

// NewDeciderWithHolderTaintJobBudgetAndCostBudget is NewDeciderWithHolder plus
// taint, job-budget, and cost-budget lookups, each consulted at decision time.
// A nil lookup means the feature is off for that dimension (untainted, within
// budget, or within cost ceiling, respectively).
func NewDeciderWithHolderTaintJobBudgetAndCostBudget(holder *reload.ReloadableEngine[policydomain.Engine], taint TaintLookup, jobBudget JobBudgetLookup, costBudget CostBudgetLookup) *Decider {
	return &Decider{policy: holder, taint: taint, jobBudget: jobBudget, costBudget: costBudget}
}

func (d *Decider) Decide(call domain.ToolCall) domain.Verdict {
	var taint domain.TaintSignal
	if d.taint != nil {
		taint = d.taint(call)
	}
	pc := policydomain.Context{
		Identity:       call.Identity,
		Tenant:         call.Tenant,
		Tool:           call.Tool,
		Method:         call.Method,
		Params:         call.Params,
		Timestamp:      call.Timestamp,
		RemoteAddr:     call.RemoteAddr,
		UserAgent:      call.UserAgent,
		Tainted:        taint.Tainted,
		JobOverBudget:  d.jobBudget != nil && d.jobBudget(call),
		CostOverBudget: d.costBudget != nil && d.costBudget(call),
	}
	engine := *d.policy.Current()
	decision := engine.Evaluate(pc)
	outcome := domain.OutcomeDeny
	switch decision.Effect {
	case policydomain.EffectAllow:
		outcome = domain.OutcomeAllow
	case policydomain.EffectNeedsApproval:
		outcome = domain.OutcomeNeedsApproval
	}
	verdict := domain.Verdict{
		Allow:   outcome == domain.OutcomeAllow,
		Outcome: outcome,
		Reason:  decision.Reason,
	}
	if taint.Tainted {
		verdict.TaintSources = taint.Sources
	}
	return verdict
}
