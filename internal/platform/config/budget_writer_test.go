package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/config"
)

func TestWriteBudgetSection_ValidBudget_PreservesEveryOtherKey(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
# a comment on features, must survive
features:
  budget_enforcement: true
budget:
  requests_per_window: 10
  window_seconds: 60
audit:
  output: stdout
`)

	newBudget := config.BudgetConfig{
		RequestsPerWindow: 25,
		WindowSeconds:     30,
		Tenants:           map[string]config.BudgetConfig{"acme": {RequestsPerWindow: 5, WindowSeconds: 60}},
	}
	if err := config.WriteBudgetSection(path, newBudget); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reload through the real Load path -- proves the file is still a
	// fully valid, loadable config, not just "some YAML".
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected the written file to reload cleanly, got: %v", err)
	}
	if cfg.Budget.RequestsPerWindow != 25 || cfg.Budget.WindowSeconds != 30 {
		t.Errorf("expected the new budget values, got %+v", cfg.Budget)
	}
	if cfg.Budget.Tenants["acme"].RequestsPerWindow != 5 {
		t.Errorf("expected the acme tenant override to survive, got %+v", cfg.Budget.Tenants)
	}

	// Every unrelated key survives -- listen/upstream/policy_file/audit
	// were never touched.
	if cfg.Listen != ":8080" || cfg.Upstream != "http://localhost:9000" || cfg.PolicyFile != "./policy.yaml" {
		t.Errorf("expected listen/upstream/policy_file untouched, got listen=%q upstream=%q policy_file=%q", cfg.Listen, cfg.Upstream, cfg.PolicyFile)
	}
	if !cfg.Features["budget_enforcement"] {
		t.Error("expected features.budget_enforcement to survive untouched")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The comment on features, a real hand-authored annotation, must
	// survive too -- this is what makes the edit "surgical" rather than
	// "re-marshal the whole struct and lose every comment".
	if !strings.Contains(string(got), "# a comment on features, must survive") {
		t.Errorf("expected the features: comment to survive the budget-only edit, got:\n%s", got)
	}
}

func TestWriteBudgetSection_NoExistingBudgetKey_Appends(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)

	newBudget := config.BudgetConfig{RequestsPerWindow: 25, WindowSeconds: 60}
	if err := config.WriteBudgetSection(path, newBudget); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected the written file to reload cleanly, got: %v", err)
	}
	if cfg.Budget.RequestsPerWindow != 25 {
		t.Errorf("expected the appended budget section to take effect, got %+v", cfg.Budget)
	}
}

func TestWriteBudgetSection_InvalidBudget_NeverTouchesDisk(t *testing.T) {
	original := `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 10
  window_seconds: 60
`
	path := writeTemp(t, original)

	// requests_per_window <= 0 is invalid whenever budget_enforcement is
	// on -- see Config.validate.
	err := config.WriteBudgetSection(path, config.BudgetConfig{RequestsPerWindow: 0, WindowSeconds: 60})
	if err == nil {
		t.Fatal("expected an error for requests_per_window <= 0, got nil")
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != original {
		t.Errorf("expected the original file to survive a rejected write untouched, got:\n%s", got)
	}
}
