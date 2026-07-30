package usecase_test

import (
	"testing"

	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
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
