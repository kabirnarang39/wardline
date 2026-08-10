package usecase_test

import (
	"testing"

	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	policyusecase "github.com/kabirnarang39/wardline/internal/features/policy/usecase"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

type fakeEngine struct {
	effect policydomain.Effect
}

func (f fakeEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	return policydomain.Decision{Effect: f.effect, Reason: "fake"}
}

func TestDecider_Allow(t *testing.T) {
	d := usecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	v := d.Decide(domain.ToolCall{Identity: "agent-abc123", Tool: "read_file"})
	if !v.Allow {
		t.Errorf("expected Allow=true, got %+v", v)
	}
}

func TestDecider_Deny(t *testing.T) {
	d := usecase.NewDecider(fakeEngine{effect: policydomain.EffectDeny})
	v := d.Decide(domain.ToolCall{Identity: "agent-abc123", Tool: "delete_file"})
	if v.Allow {
		t.Errorf("expected Allow=false, got %+v", v)
	}
	if v.Outcome != domain.OutcomeDeny {
		t.Errorf("expected deny outcome, got %q", v.Outcome)
	}
}

func TestDecide_NeedsApprovalOutcome(t *testing.T) {
	var eng policydomain.Engine = fakeEngine{effect: policydomain.EffectNeedsApproval}
	d := usecase.NewDeciderWithHolder(reload.NewReloadableEngine(&eng))
	v := d.Decide(domain.ToolCall{Identity: "alice", Tool: "delete", Method: "tools/call"})
	if v.Outcome != domain.OutcomeNeedsApproval {
		t.Fatalf("expected needs_approval outcome, got %q", v.Outcome)
	}
	if v.Allow {
		t.Fatal("needs_approval must not be Allow")
	}
}

// recordingEngine captures the Context it was last called with, so a test
// can assert on fields (like Tenant) that fakeEngine's fixed-effect shape
// has no way to observe.
type recordingEngine struct {
	captured policydomain.Context
}

func (r *recordingEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	r.captured = ctx
	return policydomain.Decision{Effect: policydomain.EffectAllow}
}

func TestDecide_PassesTenantToPolicyContext(t *testing.T) {
	engine := &recordingEngine{}
	d := usecase.NewDecider(engine)
	d.Decide(domain.ToolCall{Identity: "alice", Tool: "search", Tenant: "acme"})
	if engine.captured.Tenant != "acme" {
		t.Fatalf("got tenant %q passed to policy engine, want \"acme\"", engine.captured.Tenant)
	}
}

// TestDecider_ReloadTakesEffectOnNextCall proves the core hot-reload
// guarantee: swapping the engine behind a Decider's ReloadableEngine
// holder is observed by that SAME Decider instance on its very next
// Decide call -- no new Decider, no restart.
func TestDecider_ReloadTakesEffectOnNextCall(t *testing.T) {
	rules := []policydomain.Rule{{Identity: "alice", Tool: "read", Effect: policydomain.EffectDeny}}
	matcher := policyusecase.NewMatcher(rules, policydomain.EffectDeny)
	var engineVal policydomain.Engine = matcher
	holder := reload.NewReloadableEngine(&engineVal)

	d := usecase.NewDeciderWithHolder(holder)

	call := domain.ToolCall{Identity: "alice", Tool: "read"}

	if got := d.Decide(call); got.Allow {
		t.Fatalf("before reload: got Allow=true, want Allow=false (denied)")
	}

	// Reload with a new matcher that allows alice.
	newRules := []policydomain.Rule{{Identity: "alice", Tool: "read", Effect: policydomain.EffectAllow}}
	newMatcher := policyusecase.NewMatcher(newRules, policydomain.EffectDeny)
	var newEngine policydomain.Engine = newMatcher
	holder.Swap(&newEngine)

	// After reload, the SAME Decider instance (not a new one) reflects
	// the new rules on its very next call -- this is the crux of the
	// hot-reload guarantee.
	if got := d.Decide(call); !got.Allow {
		t.Fatalf("after reload: got Allow=false, want Allow=true -- Decider is not reading through the ReloadableEngine on every call")
	}
}

// TestDecide_TaintLookupSetsContextTainted proves the taint lookup, when
// supplied, populates Context.Tainted the policy engine reads — and that a nil
// lookup (taint_tracking off) leaves it false.
func TestDecide_TaintLookupSetsContextTainted(t *testing.T) {
	call := domain.ToolCall{Identity: "alice", Tool: "delete", Tenant: "acme"}

	// nil lookup -> untainted.
	engineOff := &recordingEngine{}
	var eOff policydomain.Engine = engineOff
	dOff := usecase.NewDeciderWithHolderAndTaint(reload.NewReloadableEngine(&eOff), nil)
	dOff.Decide(call)
	if engineOff.captured.Tainted {
		t.Errorf("nil taint lookup should leave Context.Tainted false")
	}

	// lookup returning true -> tainted.
	engineOn := &recordingEngine{}
	var eOn policydomain.Engine = engineOn
	dOn := usecase.NewDeciderWithHolderAndTaint(reload.NewReloadableEngine(&eOn), func(domain.ToolCall) bool { return true })
	dOn.Decide(call)
	if !engineOn.captured.Tainted {
		t.Errorf("taint lookup returning true should set Context.Tainted")
	}
}

func TestDecide_JobBudgetLookupSetsContextJobOverBudget(t *testing.T) {
	call := domain.ToolCall{Identity: "alice", Tool: "delete", Tenant: "acme"}

	engineOff := &recordingEngine{}
	var eOff policydomain.Engine = engineOff
	dOff := usecase.NewDeciderWithHolderTaintAndJobBudget(reload.NewReloadableEngine(&eOff), nil, nil)
	dOff.Decide(call)
	if engineOff.captured.JobOverBudget {
		t.Errorf("nil job-budget lookup should leave Context.JobOverBudget false")
	}

	engineOn := &recordingEngine{}
	var eOn policydomain.Engine = engineOn
	dOn := usecase.NewDeciderWithHolderTaintAndJobBudget(reload.NewReloadableEngine(&eOn), nil, func(domain.ToolCall) bool { return true })
	dOn.Decide(call)
	if !engineOn.captured.JobOverBudget {
		t.Errorf("job-budget lookup returning true should set Context.JobOverBudget")
	}
}
