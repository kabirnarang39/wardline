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

func TestLoad_TracingDisabledByDefaultNoValidation(t *testing.T) {
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
	if cfg.Tracing.OTLPEndpoint != "" {
		t.Errorf("expected empty OTLPEndpoint when unset, got %+v", cfg.Tracing)
	}
}

func TestLoad_TracingEnabledValid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  otel_tracing: true
tracing:
  otlp_endpoint: "localhost:4318"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Tracing.OTLPEndpoint != "localhost:4318" {
		t.Errorf("unexpected OTLPEndpoint: %q", cfg.Tracing.OTLPEndpoint)
	}
	if cfg.Tracing.ServiceName != "wardline" {
		t.Errorf("expected ServiceName to default to %q, got %q", "wardline", cfg.Tracing.ServiceName)
	}
}

func TestLoad_TracingEnabledCustomServiceName(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  otel_tracing: true
tracing:
  otlp_endpoint: "localhost:4318"
  service_name: "wardline-prod"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Tracing.ServiceName != "wardline-prod" {
		t.Errorf("expected custom ServiceName to be preserved, got %q", cfg.Tracing.ServiceName)
	}
}

func TestLoad_TracingEnabledMissingEndpoint(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  otel_tracing: true
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when otel_tracing is on but otlp_endpoint is unset")
	}
}

func TestLoad_PostgresStorageEnabledMissingDSN(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  postgres_storage: true
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error: postgres_storage on with empty audit.postgres_dsn")
	}
}

func TestLoad_PostgresStorageEnabledWithDSNNoOutputRequired(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  postgres_storage: true
audit:
  postgres_dsn: "postgres://user:pass@localhost:5432/wardline?sslmode=disable"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error with postgres_storage on and audit.postgres_dsn set: %v", err)
	}
	if cfg.Audit.PostgresDSN != "postgres://user:pass@localhost:5432/wardline?sslmode=disable" {
		t.Errorf("unexpected Audit.PostgresDSN: %q", cfg.Audit.PostgresDSN)
	}
}

func TestLoad_PostgresStorageDisabledOutputStillRequired(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error: audit.output must still be required when postgres_storage is off (backward compatibility)")
	}
}

func TestLoad_PostgresStorageDisabledDSNSetIsIgnored(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
  postgres_dsn: "postgres://leftover-config-from-before"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: audit.postgres_dsn set while postgres_storage is off should be ignored, not validated, got: %v", err)
	}
	if cfg.Audit.Output != "stdout" {
		t.Errorf("unexpected Audit.Output: %q", cfg.Audit.Output)
	}
}

func TestLoad_CredentialIssuanceDisabledByDefaultNoValidation(t *testing.T) {
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
	if cfg.Credential.IdentitiesFile != "" {
		t.Errorf("expected empty Credential.IdentitiesFile when unset, got %q", cfg.Credential.IdentitiesFile)
	}
}

func TestLoad_CredentialIssuanceEnabledValid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  credential_issuance: true
credential:
  identities_file: "./credentials.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Credential.IdentitiesFile != "./credentials.yaml" {
		t.Errorf("unexpected Credential.IdentitiesFile: %q", cfg.Credential.IdentitiesFile)
	}
}

func TestLoad_CredentialIssuanceEnabledMissingIdentitiesFile(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  credential_issuance: true
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when credential_issuance is on but credential.identities_file is unset")
	}
}

func TestLoad_RBACDisabledByDefaultNoValidation(t *testing.T) {
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
	if cfg.RBAC.ConfigFile != "" {
		t.Errorf("expected empty RBAC.ConfigFile when unset, got %q", cfg.RBAC.ConfigFile)
	}
}

func TestLoad_RBACEnabledValid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  rbac: true
rbac:
  config_file: "./rbac.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RBAC.ConfigFile != "./rbac.yaml" {
		t.Errorf("unexpected RBAC.ConfigFile: %q", cfg.RBAC.ConfigFile)
	}
}

func TestLoad_RBACEnabledMissingConfigFile(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  rbac: true
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when rbac is on but rbac.config_file is unset")
	}
}

func TestLoad_PolicyBackendCedarAccepted(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.cedar.example"
policy_backend: cedar
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PolicyBackend != "cedar" {
		t.Errorf("expected cedar, got %q", cfg.PolicyBackend)
	}
}

func TestLoad_PolicyBackendUnknownStillRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
policy_backend: rego2
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for an unrecognized policy_backend value")
	}
}
