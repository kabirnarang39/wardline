package cedar_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/policy/adapter/cedar"
)

// FuzzNewCedarEngine guards the Cedar policy parser's real attack
// surface: the dashboard's policy editor (see WritePolicySection and
// siblings) writes operator-supplied Cedar source that reaches this
// exact function to validate it BEFORE persisting, and
// `wardline validate-config`/`serve` parse whatever's on disk at
// startup -- either way, malformed input reaching a third-party parser
// (cedar-go, not code this repo controls) causing a panic is a real
// crash surface, not a theoretical one. Contract under fuzzing is the
// same as the SCIM filter and config YAML fuzz tests: NewCedarEngine
// must never panic and must always return, regardless of input --
// whether a well-formed policy's own semantics evaluate correctly is
// the existing table tests' job, not this one's.
func FuzzNewCedarEngine(f *testing.F) {
	seeds := []string{
		``,
		`permit(principal, action, resource);`,
		`permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);`,
		`forbid(principal, action, resource) when { context.params has "confirm" && context.params.confirm == false };`,
		`this is not { valid cedar`,
		`permit(principal, action, resource) when { principal == }`,
		`((((((((((((((((((((`,
		`permit(principal == Wardline::Identity::"` + string(make([]byte, 200)) + `", action, resource);`,
		`// just a comment`,
		`permit(principal, action, resource) unless { true };`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, source string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewCedarEngine panicked on input %q: %v", source, r)
			}
		}()
		_, _ = cedar.NewCedarEngine("fuzz.cedar", []byte(source))
	})
}
