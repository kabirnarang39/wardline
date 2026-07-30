package cedar_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/policy/adapter/cedar"
	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

const allowDenySource = `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);
`

func TestCedarEngine_Allow(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q (reason: %q)", got.Effect, got.Reason)
	}
	if got.Reason == "" {
		t.Error("expected a non-empty reason on allow")
	}
}

func TestCedarEngine_DenyWrongIdentity(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "someone-else", Tool: "read_file"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny, got %q", got.Effect)
	}
	if got.Reason == "" {
		t.Error("expected a non-empty default reason for an unmatched request")
	}
}

func TestCedarEngine_DenyWrongTool(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "delete_file"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny, got %q", got.Effect)
	}
}

const paramsPathSource = `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
) when {
  context.params.arguments.path like "/safe/*"
};
`

func TestCedarEngine_BranchesOnParams(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(paramsPathSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		params string
		want   domain.Effect
	}{
		{"safe path", `{"name":"read_file","arguments":{"path":"/safe/x"}}`, domain.EffectAllow},
		{"unsafe path", `{"name":"read_file","arguments":{"path":"/unsafe/x"}}`, domain.EffectDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Evaluate(domain.Context{
				Identity: "agent-abc123",
				Tool:     "read_file",
				Params:   []byte(tc.params),
			})
			if got.Effect != tc.want {
				t.Errorf("expected %q, got %q (reason: %q)", tc.want, got.Effect, got.Reason)
			}
		})
	}
}

const emptyParamsHasGuardSource = `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
) when {
  !(context.params has arguments)
};
`

// TestCedarEngine_EmptyParamsDoesNotErrorOnHasGuard proves an empty
// pc.Params still produces a usable (empty, not absent) context.params
// Record — a policy checking `context.params has arguments` must not
// error out, it must see "no such key" cleanly.
func TestCedarEngine_EmptyParamsDoesNotErrorOnHasGuard(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(emptyParamsHasGuardSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow (empty params, no 'arguments' key), got %q (reason: %q)", got.Effect, got.Reason)
	}
}

const remoteAddrAndTimestampSource = `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
) when {
  context.remote_addr == "10.0.0.5:54321" &&
  context.timestamp == "2026-07-27T10:00:00Z"
};
`

func TestCedarEngine_RemoteAddrAndTimestampReachContext(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(remoteAddrAndTimestampSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{
		Identity:   "agent-abc123",
		Tool:       "read_file",
		RemoteAddr: "10.0.0.5:54321",
		Timestamp:  time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
	})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q (reason: %q)", got.Effect, got.Reason)
	}

	got = e.Evaluate(domain.Context{
		Identity:   "agent-abc123",
		Tool:       "read_file",
		RemoteAddr: "10.0.0.6:1",
		Timestamp:  time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
	})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny when remote_addr doesn't match, got %q", got.Effect)
	}
}

func TestCedarEngine_MalformedParamsFailsClosedAtEvaluation(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Hand-constructed invalid JSON, bypassing the normal parse path (which
	// never produces malformed Params) -- defensive coverage only.
	got := e.Evaluate(domain.Context{
		Identity: "agent-abc123",
		Tool:     "read_file",
		Params:   []byte(`{not valid json`),
	})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny for malformed params, got %q", got.Effect)
	}
	if got.Reason == "" {
		t.Error("expected a non-empty reason explaining the decode failure")
	}
}

// TestCedarEngine_ForbidWithErroringWhenClauseFailsClosed is the finding-#1
// regression test: Cedar does NOT fail closed when a policy's when/unless
// clause errors at evaluation time -- it drops the erroring policy from the
// decision entirely. An erroring `forbid` (Cedar's denylist mechanism) must
// not be silently discarded in favor of a separately-matching `permit`; the
// engine must fail closed (deny) whenever diag.Errors is non-empty,
// regardless of Cedar's own decision.
const permitAndFragileForbidSource = `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);

forbid(principal, action, resource) when {
  context.params.arguments.path like "/etc/*"
};
`

func TestCedarEngine_ForbidWithErroringWhenClauseFailsClosed(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(permitAndFragileForbidSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Params omit "arguments" entirely, so the forbid's when clause
	// (context.params.arguments.path) errors ("record does not have the
	// attribute \"arguments\"") rather than evaluating to false. Cedar
	// drops the forbid policy from the decision; without a fail-closed
	// check, the unconditional permit above would win and this would be
	// allowed -- an attacker bypassing a forbid-based denylist by simply
	// omitting the field it inspects.
	got := e.Evaluate(domain.Context{
		Identity: "agent-abc123",
		Tool:     "read_file",
		Params:   []byte(`{"name":"read_file"}`),
	})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("expected deny (fail closed on policy evaluation error), got %q (reason: %q)", got.Effect, got.Reason)
	}
	if got.Reason == "" || got.Reason == "cedar: no matching permit policy" {
		t.Errorf("expected a specific evaluation-error reason, got generic/empty reason %q", got.Reason)
	}
}

// TestCedarEngine_DenyReasonNamesTheForbidPolicy covers finding #4: a deny
// caused by an explicit, unconditional (non-erroring) forbid policy must be
// reported with the specific policy that caused it (via diag.Reasons), not
// the generic "no matching permit policy" fallback that applies only when
// nothing matched at all.
const permitAndUnconditionalForbidSource = `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);

forbid(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);
`

func TestCedarEngine_DenyReasonNamesTheForbidPolicy(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(permitAndUnconditionalForbidSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("expected deny (forbid overrides permit), got %q (reason: %q)", got.Effect, got.Reason)
	}
	if got.Reason == "" || got.Reason == "cedar: no matching permit policy" {
		t.Errorf("expected the deny reason to name the matching forbid policy via diag.Reasons, got generic/empty reason %q", got.Reason)
	}
}

// TestCedarEngine_FloatParamsDeniedNotCoerced pins finding #3: Cedar's type
// system has no float and no null (and Long is a bounded 64-bit integer), so
// decoding a JSON float, a JSON null, or an out-of-range integer into a
// Cedar value fails and the adapter's existing fail-closed-on-decode-error
// behavior denies the call outright -- regardless of any policy. This is a
// deliberate, documented limitation (see README.md and policy.cedar.example),
// not a bug; this test pins the behavior so a future change doesn't
// silently alter it without updating those docs.
func TestCedarEngine_FloatParamsDeniedNotCoerced(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		params string
	}{
		{"json float", `{"name":"read_file","arguments":{"temperature":0.7}}`},
		{"json null", `{"name":"read_file","arguments":{"optional":null}}`},
		{"out-of-range integer", `{"name":"read_file","arguments":{"big":18446744073709551615}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Evaluate(domain.Context{
				Identity: "agent-abc123",
				Tool:     "read_file",
				Params:   []byte(tc.params),
			})
			if got.Effect != domain.EffectDeny {
				t.Errorf("expected deny (fail closed on undecodable param type), got %q (reason: %q)", got.Effect, got.Reason)
			}
			if got.Reason == "" {
				t.Error("expected a non-empty reason explaining the decode failure")
			}
		})
	}
}

const tenantScopedSource = `
permit(
  principal == Wardline::Identity::"alice",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"search"
) when {
  context.tenant == "acme"
};
`

// TestCedarEngine_TenantReachesContext proves domain.Context.Tenant is
// wired through to context.tenant, not just present on the struct.
func TestCedarEngine_TenantReachesContext(t *testing.T) {
	e, err := cedar.NewCedarEngine("tenant.cedar", []byte(tenantScopedSource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := e.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: "acme"})
	if got.Effect != domain.EffectAllow {
		t.Fatalf("acme tenant: got %v, want allow (reason: %q)", got.Effect, got.Reason)
	}

	got = e.Evaluate(domain.Context{Identity: "alice", Tool: "search", Tenant: "widgets-inc"})
	if got.Effect != domain.EffectDeny {
		t.Fatalf("different tenant: got %v, want deny", got.Effect)
	}
}

// TestCedarEngine_TenantFieldAdditiveDoesNotAffectExistingPolicy proves the
// new context.tenant key is purely additive: evaluating the exact same
// Context (same identity, same tool) against a policy fixture that never
// references context.tenant (allowDenySource, already used above) must
// produce the identical Decision — same Effect AND same Reason — whether
// Context.Tenant is unset or set to some value.
func TestCedarEngine_TenantFieldAdditiveDoesNotAffectExistingPolicy(t *testing.T) {
	e, err := cedar.NewCedarEngine("policy.cedar", []byte(allowDenySource))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	withoutTenant := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Tenant: ""})
	withTenant := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Tenant: "acme"})
	if withoutTenant != withTenant {
		t.Errorf("expected identical Decision regardless of Tenant, got %+v (Tenant unset) vs %+v (Tenant=acme)", withoutTenant, withTenant)
	}
	if withTenant.Effect != domain.EffectAllow {
		t.Errorf("expected allow (existing policy ignores tenant), got %q (reason: %q)", withTenant.Effect, withTenant.Reason)
	}
}

func TestNewCedarEngine_SyntaxError(t *testing.T) {
	_, err := cedar.NewCedarEngine("bad.cedar", []byte(`this is not { valid cedar`))
	if err == nil {
		t.Fatal("expected a syntax error, got nil")
	}
}

func TestLoadCedarFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")
	if err := os.WriteFile(path, []byte(allowDenySource), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := cedar.LoadCedarFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q", got.Effect)
	}
}

func TestLoadCedarFile_MissingFile(t *testing.T) {
	_, err := cedar.LoadCedarFile("/nonexistent/policy.cedar")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
