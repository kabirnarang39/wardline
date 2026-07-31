package domain_test

import (
	"testing"
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/policygen/domain"
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

func TestInfer_OnlyAllowAndPassthroughDecisionsProduceRules(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("default", "alice", "read_file", "allow"),
		entry("default", "bob", "read_file", "deny"),
		entry("default", "carol", "read_file", "throttled"),
		entry("default", "dave", "read_file", "blocked"),
		entry("default", "erin", "read_file", "error"),
		entry("default", "frank", "read_file", "passthrough"),
	}
	rules := domain.Infer(entries)
	if len(rules) != 2 {
		t.Fatalf("expected exactly 2 rules (alice's allow, frank's passthrough), got %d: %+v", len(rules), rules)
	}
	identities := map[string]bool{}
	for _, r := range rules {
		identities[r.Identity] = true
		if r.Effect != policydomain.EffectAllow {
			t.Errorf("expected every generated rule to be effect allow, got %q for identity %q", r.Effect, r.Identity)
		}
	}
	if !identities["alice"] || !identities["frank"] {
		t.Errorf("expected rules for alice (allow) and frank (passthrough), got identities: %+v", identities)
	}
}

func TestInfer_DedupesRepeatedTriple(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("default", "alice", "read_file", "allow"),
		entry("default", "alice", "read_file", "allow"),
		entry("default", "alice", "read_file", "passthrough"),
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

func TestInfer_PreservesEmptyTenantAsGiven(t *testing.T) {
	entries := []auditdomain.Entry{
		entry("", "alice", "read_file", "allow"),
	}
	rules := domain.Infer(entries)
	if len(rules) != 1 || rules[0].Tenant != "" {
		t.Fatalf("expected 1 rule with Tenant == \"\", got %+v", rules)
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
