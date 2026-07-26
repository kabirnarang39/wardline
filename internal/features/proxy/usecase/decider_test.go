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

func (f fakeEngine) Evaluate(identity, tool string) policydomain.Decision {
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
