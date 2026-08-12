package opa_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"
)

// FuzzNewOPAEngine is the OPA/Rego twin of the Cedar parser's own fuzz
// test: the dashboard's policy editor (see WritePolicySection and
// siblings) writes operator-supplied Rego source that reaches this
// exact function to validate it BEFORE persisting, and
// `wardline validate-config`/`serve` parse whatever's on disk at
// startup. OPA's own ast.ParseModule is a mature, widely-fuzzed
// upstream project, but NewOPAEngine wraps it with wardline-specific
// logic (the package-path check) that runs on every input regardless --
// the contract under fuzzing is the same as every other parser fuzzed
// this session: never panic, always return, regardless of input.
func FuzzNewOPAEngine(f *testing.F) {
	seeds := []string{
		``,
		`package wardline.authz

default allow = false

allow {
	input.identity == "agent-abc123"
	input.tool == "read_file"
}
`,
		`package wardline.authz`,
		`package wrong.package`,
		`this is not valid rego at all {{{`,
		`package wardline.authz

allow { input.identity == "` + string(make([]byte, 200)) + `" }
`,
		`package wardline.authz
import future.keywords.in
allow { input.tool in ["read_file", "write_file"] }
`,
		`# just a comment`,
		`package wardline.authz
allow { 1 / 0 }
`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, source string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewOPAEngine panicked on input %q: %v", source, r)
			}
		}()
		_, _ = opa.NewOPAEngine("fuzz.rego", []byte(source))
	})
}
