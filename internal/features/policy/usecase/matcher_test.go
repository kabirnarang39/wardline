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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Evaluate(domain.Context{Identity: tc.identity, Tool: tc.tool})
			if got.Effect != tc.want {
				t.Errorf("Evaluate(%q, %q) = %q, want %q", tc.identity, tc.tool, got.Effect, tc.want)
			}
		})
	}
}

// TestMatcher_FirstMatchWinsEvenAgainstLaterWildcard proves first-match-wins
// respects rule order regardless of effect, not just "the first allow wins":
// an earlier specific deny must beat a later wildcard allow for the same
// identity+tool, which "exact match allow" above doesn't exercise (there,
// the first matching rule already happens to be the allow).
func TestMatcher_FirstMatchWinsEvenAgainstLaterWildcard(t *testing.T) {
	rules := []domain.Rule{
		{Identity: "agent-abc123", Tool: "delete_file", Effect: domain.EffectDeny},
		{Identity: "agent-abc123", Tool: "*", Effect: domain.EffectAllow},
	}
	m := usecase.NewMatcher(rules, domain.EffectDeny)

	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "delete_file"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected earlier specific deny to win over later wildcard allow, got %q", got.Effect)
	}

	got = m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected wildcard allow to still catch a non-matching tool, got %q", got.Effect)
	}
}

func TestMatcher_DefaultAllow(t *testing.T) {
	m := usecase.NewMatcher(nil, domain.EffectAllow)
	got := m.Evaluate(domain.Context{Identity: "anyone", Tool: "anything"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected default allow, got %q", got.Effect)
	}
}
