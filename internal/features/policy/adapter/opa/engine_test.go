package opa_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"
	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

const allowDenySource = `package wardline.authz

default allow = false

allow {
	input.identity == "agent-abc123"
	input.tool == "read_file"
}

reason = "matched read_file rule" {
	allow
}
`

func TestOPAEngine_Allow(t *testing.T) {
	e, err := opa.NewOPAEngine("policy.rego", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q", got.Effect)
	}
	if got.Reason != "matched read_file rule" {
		t.Errorf("expected reason from rule, got %q", got.Reason)
	}
}

func TestOPAEngine_DenyNoReason(t *testing.T) {
	e, err := opa.NewOPAEngine("policy.rego", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "someone-else", Tool: "read_file"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny, got %q", got.Effect)
	}
	if got.Reason == "" {
		t.Error("expected a non-empty default reason when the rule produced no reason key")
	}
}

const paramsAndTimeSource = `package wardline.authz

default allow = false

allow {
	input.identity == "agent-abc123"
	startswith(input.params.arguments.path, "/safe/")
	ns := time.parse_rfc3339_ns(input.timestamp)
	clock := time.clock([ns, "UTC"])
	clock[0] >= 9
	clock[0] < 17
}

reason = "matched safe-path business-hours rule" {
	allow
}
`

func TestOPAEngine_BranchesOnParamsAndTimestamp(t *testing.T) {
	e, err := opa.NewOPAEngine("policy.rego", []byte(paramsAndTimeSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	businessHours := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	afterHours := time.Date(2026, 7, 27, 23, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		params    string
		timestamp time.Time
		want      domain.Effect
	}{
		{"safe path in business hours", `{"name":"read_file","arguments":{"path":"/safe/x"}}`, businessHours, domain.EffectAllow},
		{"unsafe path in business hours", `{"name":"read_file","arguments":{"path":"/unsafe/x"}}`, businessHours, domain.EffectDeny},
		{"safe path after hours", `{"name":"read_file","arguments":{"path":"/safe/x"}}`, afterHours, domain.EffectDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Evaluate(domain.Context{
				Identity:  "agent-abc123",
				Tool:      "read_file",
				Params:    []byte(tc.params),
				Timestamp: tc.timestamp,
			})
			if got.Effect != tc.want {
				t.Errorf("expected %q, got %q (reason: %q)", tc.want, got.Effect, got.Reason)
			}
		})
	}
}

const remoteAddrAndUserAgentSource = `package wardline.authz

default allow = false

allow {
	input.identity == "agent-abc123"
	input.remote_addr == "10.0.0.5:54321"
	input.user_agent == "some-agent/1.0"
}
`

// TestOPAEngine_RemoteAddrAndUserAgentReachRego proves remote_addr and
// user_agent — documented in the README as available Rego input fields —
// actually reach the policy, not just params and timestamp.
func TestOPAEngine_RemoteAddrAndUserAgentReachRego(t *testing.T) {
	e, err := opa.NewOPAEngine("policy.rego", []byte(remoteAddrAndUserAgentSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := e.Evaluate(domain.Context{
		Identity:   "agent-abc123",
		Tool:       "read_file",
		RemoteAddr: "10.0.0.5:54321",
		UserAgent:  "some-agent/1.0",
	})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow when remote_addr/user_agent match, got %q (reason: %q)", got.Effect, got.Reason)
	}

	got = e.Evaluate(domain.Context{
		Identity:   "agent-abc123",
		Tool:       "read_file",
		RemoteAddr: "10.0.0.5:54321",
		UserAgent:  "some-other-agent/2.0",
	})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny when user_agent doesn't match, got %q", got.Effect)
	}
}

const largeIntDenylistSource = `package wardline.authz

default allow = false

denylist := {12345678901234567}

allow {
	not denylist[input.params.account_id]
}
`

// TestOPAEngine_LargeIntegerParamsNotRounded proves a Rego denylist keyed
// on an integer beyond float64's 53-bit integer precision (2^53) still
// matches an identical integer sent in the request body. Before the fix,
// decoding params via json.Unmarshal into `any` converted every JSON
// number to float64, which can silently round a large integer to a
// different value that no longer matches the denylist literal — a
// security bypass, not just a precision quirk.
func TestOPAEngine_LargeIntegerParamsNotRounded(t *testing.T) {
	e, err := opa.NewOPAEngine("denylist.rego", []byte(largeIntDenylistSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{
		Identity: "agent-abc123",
		Tool:     "read_file",
		Params:   []byte(`{"account_id":12345678901234567}`),
	})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny (denylisted account_id preserved exactly), got %q (reason: %q)", got.Effect, got.Reason)
	}
}

func TestOPAEngine_NoRuleAtAll(t *testing.T) {
	// A package with zero rules under wardline.authz evaluates to an empty
	// object (verified empirically: rs[0].Expressions[0].Value is
	// map[string]interface{}{}, not an empty ResultSet) — the "allow" key
	// is simply absent, which must fail closed rather than panic or
	// silently allow.
	e, err := opa.NewOPAEngine("empty.rego", []byte(`package wardline.authz
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny when no rule defines allow at all, got %q", got.Effect)
	}
	if got.Reason == "" {
		t.Error("expected a non-empty reason explaining the missing decision")
	}
}

func TestOPAEngine_NonBooleanAllow(t *testing.T) {
	// A malformed policy where allow resolves to a non-boolean value must
	// never be silently treated as truthy — fail closed instead.
	e, err := opa.NewOPAEngine("nonbool.rego", []byte(`package wardline.authz

allow = "yes"
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny when allow is a non-boolean value, got %q", got.Effect)
	}
	if got.Reason == "" {
		t.Error("expected a non-empty reason explaining the invalid allow value")
	}
}

func TestNewOPAEngine_SyntaxError(t *testing.T) {
	_, err := opa.NewOPAEngine("bad.rego", []byte(`package wardline.authz

allow {
	this is not valid rego
`))
	if err == nil {
		t.Fatal("expected a syntax error, got nil")
	}
}

func TestNewOPAEngine_WrongPackage(t *testing.T) {
	_, err := opa.NewOPAEngine("wrong.rego", []byte(`package something.else

allow = true
`))
	if err == nil {
		t.Fatal("expected a wrong-package error, got nil")
	}
}

func TestLoadRegoFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(path, []byte(allowDenySource), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := opa.LoadRegoFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q", got.Effect)
	}
}

const tenantScopedSource = `package wardline.authz

default allow = false

allow {
	input.identity == "alice"
	input.tool == "search"
	input.tenant == "acme"
}
`

// TestOPAEngine_TenantReachesRegoInput proves domain.Context.Tenant is
// wired through to input.tenant, not just present on the struct.
func TestOPAEngine_TenantReachesRegoInput(t *testing.T) {
	e, err := opa.NewOPAEngine("tenant.rego", []byte(tenantScopedSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := e.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: "acme"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("acme tenant: got %v, want allow", got.Effect)
	}

	got = e.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: "widgets-inc"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("different tenant: got %v, want deny", got.Effect)
	}
}

// TestOPAEngine_TenantFieldAdditiveDoesNotAffectExistingPolicy proves the
// new tenant input field is purely additive: evaluating the exact same
// Context (same identity, same tool) against a policy fixture that never
// references input.tenant (allowDenySource, already used above) must
// produce the identical Decision — same Effect AND same Reason — whether
// Context.Tenant is unset or set to some value.
func TestOPAEngine_TenantFieldAdditiveDoesNotAffectExistingPolicy(t *testing.T) {
	e, err := opa.NewOPAEngine("policy.rego", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	withoutTenant := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Tenant: ""})
	withTenant := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Tenant: "acme"})
	if withoutTenant != withTenant {
		t.Errorf("expected identical Decision regardless of Tenant, got %+v (Tenant unset) vs %+v (Tenant=acme)", withoutTenant, withTenant)
	}
	if withTenant.Effect != domain.EffectAllow {
		t.Errorf("expected allow (existing policy ignores tenant), got %q", withTenant.Effect)
	}
}

func TestLoadRegoFile_MissingFile(t *testing.T) {
	_, err := opa.LoadRegoFile("/nonexistent/policy.rego")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
