package domain_test

import (
	"testing"
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/policygen/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func entry(tenant, identity, tool, decision string) auditdomain.Entry {
	return auditdomain.Entry{
		Timestamp: time.Now(),
		Tenant:    tenant,
		Identity:  identity,
		Tool:      tool,
		Decision:  decision,
	}
}

func TestInfer_EmptyInputReturnsNoRules(t *testing.T) {
	rules := domain.Infer(nil)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from empty input, got %d", len(rules))
	}
}

func TestInfer_OnlyAllowDecisionsProduceRules(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("default", "alice", "read_file", "allow"),
		entry("default", "bob", "read_file", "deny"),
		entry("default", "carol", "read_file", "throttled"),
		entry("default", "dave", "read_file", "blocked"),
		entry("default", "erin", "read_file", "error"),
		entry("default", "frank", "read_file", "passthrough"),
	}
	rules := domain.Infer(entries)
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 rule (alice's allow), got %d: %+v", len(rules), rules)
	}
	if rules[0].Identity != "alice" {
		t.Errorf("expected the only rule to be alice's, got %+v", rules[0])
	}
	if rules[0].Effect != policydomain.EffectAllow {
		t.Errorf("expected effect allow, got %q", rules[0].Effect)
	}
}

// TestInfer_ExcludesPassthroughEvenWithALegitimateLookingToolName is the
// Critical-1 regression test: a passthrough entry's Tool field holds a raw
// JSON-RPC method name that policy never evaluated (and Identity/Tenant are
// caller-supplied on the default header-auth path), so it must never be
// treated as an observed grant -- no matter how much the method name looks
// like a real tool.
func TestInfer_ExcludesPassthroughEvenWithALegitimateLookingToolName(t *testing.T) {
	rules := domain.Infer([]auditdomain.Entry{
		entry("acme", "attacker", "read_file", "passthrough"),
	})
	if len(rules) != 0 {
		t.Fatalf("expected passthrough entries to produce no rules, got %+v", rules)
	}
}

// TestInfer_ExcludesWildcardToolEvenWhenAllowed is Critical 1's defense in
// depth: no observed traffic may synthesize the "*" rule
// policy/usecase.Matcher treats as matching every tool.
func TestInfer_ExcludesWildcardToolEvenWhenAllowed(t *testing.T) {
	for _, decision := range []string{"allow", "passthrough"} {
		rules := domain.Infer([]auditdomain.Entry{
			entry("acme", "attacker", "*", decision),
		})
		if len(rules) != 0 {
			t.Errorf("decision %q with tool \"*\": expected no rules, got %+v", decision, rules)
		}
	}
}

// TestInfer_ExcludesEmptyIdentityOrTool is Critical 2's regression test:
// policy/adapter.LoadFile rejects both an empty identity and an empty tool,
// so emitting such a rule would produce a file the real loader refuses --
// and the default HeaderIdentity authenticator yields Identity == "" for any
// request without an identity header.
func TestInfer_ExcludesEmptyIdentityOrTool(t *testing.T) {
	rules := domain.Infer([]auditdomain.Entry{
		entry("acme", "", "read_file", "allow"),
		entry("acme", "alice", "", "allow"),
	})
	if len(rules) != 0 {
		t.Fatalf("expected entries with an empty identity or tool to produce no rules, got %+v", rules)
	}
}

func TestInfer_DedupesRepeatedTriple(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("default", "alice", "read_file", "allow"),
		entry("default", "alice", "read_file", "allow"),
	}
	rules := domain.Infer(entries)
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 deduped rule, got %d: %+v", len(rules), rules)
	}
}

func TestInfer_DistinguishesByTenant(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("acme", "alice", "read_file", "allow"),
		entry("widgets-inc", "alice", "read_file", "allow"),
	}
	rules := domain.Infer(entries)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (same identity+tool, different tenant), got %d: %+v", len(rules), rules)
	}
}

// TestInfer_NormalizesEmptyTenantToDefault is Important 4's regression test:
// policy.domain.Rule treats Tenant == "" as global (matches every tenant), so
// passing an untenanted entry straight through would silently turn one
// tenant's traffic into a cross-tenant allow. Normalizing to tenant.Default
// matches the read-time defaulting audit/adapter's readers already do.
func TestInfer_NormalizesEmptyTenantToDefault(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("", "alice", "read_file", "allow"),
	}
	rules := domain.Infer(entries)
	if len(rules) != 1 || rules[0].Tenant != tenant.Default {
		t.Fatalf("expected 1 rule with Tenant == %q, got %+v", tenant.Default, rules)
	}
}

func TestInfer_SortsByTenantThenIdentityThenTool(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("widgets-inc", "bob", "write_file", "allow"),
		entry("acme", "zoe", "read_file", "allow"),
		entry("acme", "alice", "write_file", "allow"),
		entry("acme", "alice", "read_file", "allow"),
	}
	rules := domain.Infer(entries)
	want := []struct{ Tenant, Identity, Tool string }{
		{"acme", "alice", "read_file"},
		{"acme", "alice", "write_file"},
		{"acme", "zoe", "read_file"},
		{"widgets-inc", "bob", "write_file"},
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d: %+v", len(want), len(rules), rules)
	}
	for i, w := range want {
		if rules[i].Tenant != w.Tenant || rules[i].Identity != w.Identity || rules[i].Tool != w.Tool {
			t.Errorf("rule %d: expected %+v, got {Tenant:%q Identity:%q Tool:%q}", i, w, rules[i].Tenant, rules[i].Identity, rules[i].Tool)
		}
	}
}
