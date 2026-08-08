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

func TestMatcher_TenantScopedRuleOnlyMatchesItsOwnTenant(t *testing.T) {
	m := usecase.NewMatcher([]domain.Rule{
		{Identity: "alice", Tool: "*", Effect: domain.EffectAllow, Tenant: "acme"},
	}, domain.EffectDeny)

	got := m.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: "acme"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("acme tenant: got %v, want allow", got.Effect)
	}

	got = m.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: "widgets-inc"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("different tenant: got %v, want deny (default)", got.Effect)
	}
}

// TestMatcher_EmptyRuleMethodDefaultsToToolsCall is the back-compat
// regression guard the widening design doc calls for: a rule written
// before Method existed (Method == "") must keep matching tools/call
// exactly as before, and must NOT match a resources/prompts request just
// because it left Method unset.
func TestMatcher_EmptyRuleMethodDefaultsToToolsCall(t *testing.T) {
	m := usecase.NewMatcher([]domain.Rule{
		{Identity: "alice", Tool: "search", Effect: domain.EffectAllow},
	}, domain.EffectDeny)

	got := m.Evaluate(domain.Context{Identity: "alice", Tool: "search", Method: "tools/call"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("explicit tools/call context: got %v, want allow", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "alice", Tool: "search"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("empty-method context (legacy caller): got %v, want allow", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "alice", Tool: "search", Method: "resources/read"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("resources/read with same tool name: got %v, want default deny (rule must not cross methods)", got.Effect)
	}
}

// TestMatcher_MethodScopedWildcardDoesNotCrossMethods proves a Tool: "*"
// rule with no Method set (defaulting to tools/call) does NOT widen to
// cover the new resources/prompts method space — an old wildcard rule
// written before this feature existed must not silently start matching
// request types its author never saw.
func TestMatcher_MethodScopedWildcardDoesNotCrossMethods(t *testing.T) {
	m := usecase.NewMatcher([]domain.Rule{
		{Identity: "alice", Tool: "*", Effect: domain.EffectAllow},
	}, domain.EffectDeny)

	got := m.Evaluate(domain.Context{Identity: "alice", Tool: "anything", Method: "tools/call"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("tools/call wildcard: got %v, want allow", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "alice", Tool: "file:///etc/passwd", Method: "resources/read"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("resources/read against a tools/call-only wildcard: got %v, want default deny", got.Effect)
	}
}

func TestMatcher_MethodScopedRuleMatchesOnlyItsMethod(t *testing.T) {
	m := usecase.NewMatcher([]domain.Rule{
		{Identity: "alice", Tool: "file:///data/report.csv", Effect: domain.EffectAllow, Method: "resources/read"},
	}, domain.EffectDeny)

	got := m.Evaluate(domain.Context{Identity: "alice", Tool: "file:///data/report.csv", Method: "resources/read"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("matching resource read: got %v, want allow", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "alice", Tool: "file:///data/report.csv", Method: "tools/call"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("same target name via tools/call: got %v, want default deny (rule is method-scoped)", got.Effect)
	}
}

func TestMatcher_UntargetedListCallOnlyMatchesWildcardOrDefault(t *testing.T) {
	m := usecase.NewMatcher([]domain.Rule{
		{Identity: "alice", Tool: "*", Effect: domain.EffectAllow, Method: "resources/list"},
		{Identity: "bob", Tool: "file:///specific", Effect: domain.EffectAllow, Method: "resources/list"},
	}, domain.EffectDeny)

	got := m.Evaluate(domain.Context{Identity: "alice", Tool: "", Method: "resources/list"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("wildcard rule against untargeted list call: got %v, want allow", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "bob", Tool: "", Method: "resources/list"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("specific-target rule against untargeted list call (empty tool never equals a specific target): got %v, want default deny", got.Effect)
	}
}

func TestMatcher_UntenantedRuleMatchesAnyTenant(t *testing.T) {
	m := usecase.NewMatcher([]domain.Rule{
		{Identity: "alice", Tool: "*", Effect: domain.EffectAllow},
	}, domain.EffectDeny)

	for _, tenantName := range []string{"acme", "widgets-inc", ""} {
		got := m.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: tenantName})
		if got.Effect != domain.EffectAllow {
			t.Fatalf("global rule, tenant %q: got %v, want allow", tenantName, got.Effect)
		}
	}
}
