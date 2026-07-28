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
