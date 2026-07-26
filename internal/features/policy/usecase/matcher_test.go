package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/policy/usecase"
)

func TestMatcher_Evaluate(t *testing.T) {
	rules := []domain.Rule{
		{Identity: "agent-abc123", Tool: "read_file", Effect: domain.EffectAllow},
		{Identity: "agent-abc123", Tool: "*", Effect: domain.EffectDeny},
	}
	m := usecase.NewMatcher(rules, domain.EffectDeny)

	cases := []struct {
		name     string
		identity string
		tool     string
		want     domain.Effect
	}{
		{"exact match allow", "agent-abc123", "read_file", domain.EffectAllow},
		{"wildcard catch-all deny", "agent-abc123", "delete_file", domain.EffectDeny},
		{"unknown identity falls to default", "agent-unknown", "read_file", domain.EffectDeny},
		{"first match wins over later wildcard", "agent-abc123", "read_file", domain.EffectAllow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Evaluate(tc.identity, tc.tool)
			if got.Effect != tc.want {
				t.Errorf("Evaluate(%q, %q) = %q, want %q", tc.identity, tc.tool, got.Effect, tc.want)
			}
		})
	}
}

func TestMatcher_DefaultAllow(t *testing.T) {
	m := usecase.NewMatcher(nil, domain.EffectAllow)
	got := m.Evaluate("anyone", "anything")
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected default allow, got %q", got.Effect)
	}
}
