package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/config"
)

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardline.yaml")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.Upstream != "http://localhost:9000" || cfg.PolicyFile != "./policy.yaml" || cfg.Audit.Output != "stdout" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	path := writeTemp(t, `listen: ""`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
}

func TestLoad_InvalidUpstreamURL(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "://not-a-url"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/wardline.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_UnknownTopLevelKey(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstrem: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for unknown top-level key (typo'd 'upstrem'), got nil")
	}
}

func TestLoad_UpstreamMissingScheme(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for upstream missing scheme/host")
	}
}

func TestLoad_UpstreamWrongScheme(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "ftp://host"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for non-http(s) upstream scheme")
	}
}

func TestLoad_UpstreamEmptyHost(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for upstream with empty host")
	}
}

func TestLoad_ValidUpstreamPopulatesUpstreamURL(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.UpstreamURL == nil {
		t.Fatal("expected UpstreamURL to be populated")
	}
	if cfg.UpstreamURL.Scheme != "http" || cfg.UpstreamURL.Host != "localhost:9000" {
		t.Errorf("unexpected UpstreamURL: %+v", cfg.UpstreamURL)
	}
}

func TestLoad_PolicyBackendDefaultsToYAML(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PolicyBackend != "yaml" {
		t.Errorf("expected policy_backend to default to %q, got %q", "yaml", cfg.PolicyBackend)
	}
}

func TestLoad_PolicyBackendOPA(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.rego"
policy_backend: opa
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PolicyBackend != "opa" {
		t.Errorf("expected policy_backend %q, got %q", "opa", cfg.PolicyBackend)
	}
}

func TestLoad_PolicyBackendInvalid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
policy_backend: cedar
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for unrecognized policy_backend value")
	}
}

func TestLoad_BudgetDisabledByDefaultNoValidation(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Budget.RequestsPerWindow != 0 || cfg.Budget.WindowSeconds != 0 {
		t.Errorf("expected zero-value Budget when unset, got %+v", cfg.Budget)
	}
}

func TestLoad_BudgetEnabledValid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Budget.RequestsPerWindow != 100 || cfg.Budget.WindowSeconds != 60 {
		t.Errorf("unexpected Budget: %+v", cfg.Budget)
	}
}

func TestLoad_BudgetWindowSecondsAboveBoundRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 86401
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when budget.window_seconds exceeds the 24h bound")
	}
}

func TestLoad_BudgetEnabledMissingLimits(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when budget_enforcement is on but requests_per_window/window_seconds are unset")
	}
}
