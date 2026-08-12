package config_test

import (
	"strings"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/config"
)

// FuzzParseBytes guards config.ParseBytes against malformed input: it
// isn't only an operator hand-editing wardline.yaml -- the dashboard's
// Policy/Budget/RBAC editors (see WriteBudgetSection and siblings) call
// this exact function to validate operator-supplied YAML BEFORE
// persisting it, so this is real attacker-adjacent surface for any
// dashboard-authenticated caller, not purely a trusted-operator path.
// A malformed document must return an error, never panic and never
// hang -- yaml.v3 decoding into a large struct with several
// recursively-typed fields (BudgetConfig.Tenants reuses BudgetConfig
// itself) is exactly the shape where a decoder edge case or an
// unbounded-recursion input could cause either.
func FuzzParseBytes(f *testing.F) {
	seeds := []string{
		``,
		`listen: ":8080"`,
		`
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`,
		`
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
features:
  budget_enforcement: true
  anomaly_detection: true
  credential_issuance: true
  rbac: true
  scim: true
  web_ui: true
  postgres_storage: true
  federation: true
  taint_tracking: true
  approval_workflow: true
  job_budget: true
  job_cost_budget: true
  otel_tracing: true
  grpc_transport: true
  spiffe_workload_identity: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    acme:
      requests_per_window: 10
      window_seconds: 60
      tenants:
        nested:
          requests_per_window: 1
          window_seconds: 1
`,
		`listen: [this, is, a, list, not, a, string]`,
		`{`,
		`}`,
		`- just a list`,
		`"unterminated string`,
		`key: !!binary "not valid base64!!!"`,
		"listen: \"\x00\x01\x02\"",
		`unknown_top_level_field: true`,
		strings.Repeat("nested:\n  ", 500) + "value: 1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseBytes panicked on input %q: %v", data, r)
			}
		}()
		_, _ = config.ParseBytes([]byte(data))
	})
}
