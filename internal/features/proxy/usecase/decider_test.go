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
