package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestLoad_GRPCTransportRequiresListenAndUpstream(t *testing.T) {
	// Flag on but grpc_listen/grpc_upstream missing -> rejected.
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
features:
  grpc_transport: true
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected error when grpc_transport is on but grpc_listen/grpc_upstream are unset")
	}

	// Both present -> accepted and parsed.
	path = writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
grpc_listen: "127.0.0.1:9090"
grpc_upstream: "127.0.0.1:9091"
features:
  grpc_transport: true
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GRPCListen != "127.0.0.1:9090" || cfg.GRPCUpstream != "127.0.0.1:9091" {
		t.Errorf("unexpected grpc config: listen=%q upstream=%q", cfg.GRPCListen, cfg.GRPCUpstream)
	}
}

func TestLoad_GRPCFieldsIgnoredWhenFlagOff(t *testing.T) {
	// Flag off: absent grpc_listen/grpc_upstream is fine, not an error.
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("grpc fields should be optional when grpc_transport is off: %v", err)
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

// TestLoad_BudgetTenantMissingRequestsPerWindowRejected proves an operator
// who adds a tenant override but forgets requests_per_window (YAML
// zero-value 0) gets a config-load error instead of a silent full outage
// for that tenant (0 >= 0 in checkAndAdvance would deny every request).
func TestLoad_BudgetTenantMissingRequestsPerWindowRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    acme:
      window_seconds: 60
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when a tenant override's requests_per_window is unset (0)")
	}
	if !strings.Contains(err.Error(), "budget.tenants.acme.requests_per_window must be > 0") {
		t.Errorf("expected a clear per-tenant error message, got %q", err.Error())
	}
}

// TestLoad_BudgetTenantZeroWindowSecondsRejected proves a tenant override
// with window_seconds <= 0 is rejected -- unvalidated, it would make the
// tenant bucket reset on every call (now.Sub(windowStart) >= 0 is always
// true), silently defeating the override entirely.
func TestLoad_BudgetTenantZeroWindowSecondsRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    acme:
      requests_per_window: 1
      window_seconds: 0
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when a tenant override's window_seconds is 0")
	}
	if !strings.Contains(err.Error(), "budget.tenants.acme.window_seconds must be > 0") {
		t.Errorf("expected a clear per-tenant error message, got %q", err.Error())
	}
}

// TestLoad_BudgetTenantEmptyKeyRejected is an M7 regression test: an
// empty-string tenant key in budget.tenants would apply the override to
// any caller resolving to Tenant == "" -- exactly the pre-upgrade-token
// tenant value (see I4) -- silently and unintentionally.
func TestLoad_BudgetTenantEmptyKeyRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    "":
      requests_per_window: 1
      window_seconds: 60
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when budget.tenants has an empty-string key")
	}
	if !strings.Contains(err.Error(), "budget.tenants must not have an empty-string tenant key") {
		t.Errorf("expected a clear empty-key error message, got %q", err.Error())
	}
}

// TestLoad_BudgetTenantValidOverrideAccepted proves a well-formed tenant
// override still loads cleanly -- the new validation isn't over-strict.
func TestLoad_BudgetTenantValidOverrideAccepted(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    acme:
      requests_per_window: 1
      window_seconds: 60
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Budget.Tenants["acme"]; got.RequestsPerWindow != 1 || got.WindowSeconds != 60 {
		t.Errorf("unexpected tenant override: %+v", got)
	}
}

// TestLoad_BudgetToolZeroRequestsPerWindowRejected mirrors
// TestLoad_BudgetTenantMissingRequestsPerWindowRejected: an unvalidated 0
// requests_per_window for a tool override would silently deny every call
// to that tool forever.
func TestLoad_BudgetToolZeroRequestsPerWindowRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tools:
    expensive_tool:
      window_seconds: 60
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when a tool override's requests_per_window is unset (0)")
	}
	if !strings.Contains(err.Error(), "budget.tools.expensive_tool.requests_per_window must be > 0") {
		t.Errorf("expected a clear per-tool error message, got %q", err.Error())
	}
}

// TestLoad_BudgetToolZeroWindowSecondsRejected mirrors
// TestLoad_BudgetTenantZeroWindowSecondsRejected.
func TestLoad_BudgetToolZeroWindowSecondsRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tools:
    expensive_tool:
      requests_per_window: 1
      window_seconds: 0
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when a tool override's window_seconds is 0")
	}
	if !strings.Contains(err.Error(), "budget.tools.expensive_tool.window_seconds must be > 0") {
		t.Errorf("expected a clear per-tool error message, got %q", err.Error())
	}
}

// TestLoad_BudgetToolEmptyKeyRejected mirrors
// TestLoad_BudgetTenantEmptyKeyRejected: an empty-string tool key is the
// same map-key-not-checked footgun budget.tenants had.
func TestLoad_BudgetToolEmptyKeyRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tools:
    "":
      requests_per_window: 1
      window_seconds: 60
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when budget.tools has an empty-string key")
	}
	if !strings.Contains(err.Error(), "budget.tools must not have an empty-string tool key") {
		t.Errorf("expected a clear empty-key error message, got %q", err.Error())
	}
}

// TestLoad_BudgetToolValidOverrideAccepted proves a well-formed tool
// override still loads cleanly -- the new validation isn't over-strict.
func TestLoad_BudgetToolValidOverrideAccepted(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 60
  tools:
    expensive_tool:
      requests_per_window: 1
      window_seconds: 60
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Budget.Tools["expensive_tool"]; got.RequestsPerWindow != 1 || got.WindowSeconds != 60 {
		t.Errorf("unexpected tool override: %+v", got)
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

// TestLoad_OIDCBootstrapRequiresIssuerJWKSAudience covers
// credential.bootstrap_source: "oidc" -- config_test.go is package
// config_test (an external test package), so this can't call
// cfg.validate() directly as the task brief's illustrative snippet does
// (validate is unexported); it round-trips through config.Load and a
// temp YAML file like every other test in this file instead.
func TestLoad_OIDCBootstrapRequiresIssuerJWKSAudience(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  bootstrap_source: "oidc"
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error for oidc bootstrap_source with no oidc config block")
	}

	path2 := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  bootstrap_source: "oidc"
  oidc:
    issuer: "https://idp.example.com/"
    jwks_uri: "https://idp.example.com/jwks.json"
    audience: "wardline"
`)
	cfg, err := config.Load(path2)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Credential.OIDC.IdentityClaim != "sub" {
		t.Errorf("expected identity_claim to default to %q, got %q", "sub", cfg.Credential.OIDC.IdentityClaim)
	}
	if cfg.Credential.OIDC.TenantClaim != "tenant" {
		t.Errorf("expected tenant_claim to default to %q, got %q", "tenant", cfg.Credential.OIDC.TenantClaim)
	}
}

// TestLoad_MTLSBootstrapRequiresHeader mirrors
// TestLoad_OIDCBootstrapRequiresIssuerJWKSAudience's shape for the third
// bootstrap source.
func TestLoad_MTLSBootstrapRequiresHeader(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  bootstrap_source: "mtls"
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error for mtls bootstrap_source with no header configured")
	}

	path2 := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  bootstrap_source: "mtls"
  mtls:
    header: "X-Wardline-Verified-Spiffe-Id"
`)
	cfg, err := config.Load(path2)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Credential.MTLS.Header != "X-Wardline-Verified-Spiffe-Id" {
		t.Errorf("expected mtls.header to round-trip, got %q", cfg.Credential.MTLS.Header)
	}
}

func TestLoad_BootstrapSourceUnknownValueRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  bootstrap_source: "ldap"
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal(`expected error for bootstrap_source neither "presharedsecret" nor "oidc"`)
	}
}

func TestLoad_BootstrapSourceDefaultsToPresharedSecret(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Credential.BootstrapSource != "presharedsecret" {
		t.Errorf(`expected bootstrap_source to default to "presharedsecret", got %q`, cfg.Credential.BootstrapSource)
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

func TestLoad_AnomalyDisabledByDefaultNoValidation(t *testing.T) {
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
	if cfg.Anomaly.Output != "" {
		t.Errorf("expected empty Anomaly.Output when unset, got %q", cfg.Anomaly.Output)
	}
}

func TestLoad_AnomalyEnabledValid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  rate_spike:
    enabled: true
    rate_multiplier: 3.0
    min_calls: 10
  deny_rate_spike:
    enabled: true
    threshold: 0.5
    min_calls: 5
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anomaly.Output != "./anomaly.jsonl" {
		t.Errorf("unexpected Anomaly.Output: %q", cfg.Anomaly.Output)
	}
	if cfg.Anomaly.RateSpike.Multiplier != 3.0 {
		t.Errorf("unexpected RateSpike.Multiplier: %v", cfg.Anomaly.RateSpike.Multiplier)
	}
}

func TestLoad_AnomalyEnabledMissingOutput(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when anomaly_detection is on but anomaly.output is unset")
	}
}

func TestLoad_AnomalyRateSpikeEnabledWithNonPositiveMultiplierErrors(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  rate_spike:
    enabled: true
    rate_multiplier: 0
    min_calls: 10
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when rate_spike is enabled with a non-positive multiplier")
	}
}

func TestLoad_AnomalyDenyRateSpikeEnabledWithOutOfRangeThresholdErrors(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  deny_rate_spike:
    enabled: true
    threshold: 1.5
    min_calls: 5
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when deny_rate_spike's threshold is outside (0, 1]")
	}
}

func TestLoad_AnomalyEnabledNonPositiveWindowSecondsErrors(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 0
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when anomaly_detection is on but window_seconds is non-positive")
	}
}

func TestLoad_AnomalyOutputSameFileAsAuditOutputErrors(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./wardline.jsonl"
  window_seconds: 60
audit:
  output: "./wardline.jsonl"
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when anomaly.output and audit.output name the same file")
	}
}

func TestLoad_AnomalyAndAuditBothStdoutIsValid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: stdout
  window_seconds: 60
audit:
  output: stdout
`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("both streams on stdout must stay valid, got %v", err)
	}
}

func TestLoad_CredentialSigningKeyFileUnsetNoValidation(t *testing.T) {
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
	if cfg.Credential.SigningKeyFile != "" {
		t.Errorf("expected empty SigningKeyFile when unset, got %q", cfg.Credential.SigningKeyFile)
	}
}

func TestLoad_CredentialSigningKeyFileSetPassesThrough(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  credential_issuance: true
credential:
  identities_file: "./credentials.yaml"
  signing_key_file: "./signing-key.pem"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Credential.SigningKeyFile != "./signing-key.pem" {
		t.Errorf("unexpected SigningKeyFile: %q", cfg.Credential.SigningKeyFile)
	}
}

func TestLoad_CredentialPreviousSigningKeyFilesPassThrough(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  credential_issuance: true
credential:
  identities_file: "./credentials.yaml"
  signing_key_file: "./signing-key.pem"
  previous_signing_key_files:
    - "./old-key-1.pem"
    - "./old-key-2.pem"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Credential.PreviousSigningKeyFiles) != 2 {
		t.Fatalf("expected 2 previous signing key files, got %d: %v", len(cfg.Credential.PreviousSigningKeyFiles), cfg.Credential.PreviousSigningKeyFiles)
	}
	if cfg.Credential.PreviousSigningKeyFiles[0] != "./old-key-1.pem" || cfg.Credential.PreviousSigningKeyFiles[1] != "./old-key-2.pem" {
		t.Errorf("unexpected previous key files: %v", cfg.Credential.PreviousSigningKeyFiles)
	}
}

func TestLoad_CredentialPreviousSigningKeyFilesDefaultEmpty(t *testing.T) {
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
	if len(cfg.Credential.PreviousSigningKeyFiles) != 0 {
		t.Errorf("expected no previous signing key files when unset, got %v", cfg.Credential.PreviousSigningKeyFiles)
	}
}

func TestLoad_FederationRequiresAnomalyDetection(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  federation: true
  anomaly_detection: false
federation:
  peers_file: "./peers.yaml"
  signing_key_file: "./key.pem"
  shared_secret_file: "./secret"
  publish_interval_seconds: 60
  min_instances_for_correlation: 2
  correlation_window_seconds: 300
  gc_interval_seconds: 600
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error when federation is on but anomaly_detection is off")
	}
}

func TestLoad_FederationMissingPeersFile(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  federation: true
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
federation:
  signing_key_file: "./key.pem"
  shared_secret_file: "./secret"
  publish_interval_seconds: 60
  min_instances_for_correlation: 2
  correlation_window_seconds: 300
  gc_interval_seconds: 600
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error when federation.peers_file is empty")
	}
}

func TestLoad_FederationMinInstancesBelowTwo(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  federation: true
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
federation:
  peers_file: "./peers.yaml"
  signing_key_file: "./key.pem"
  shared_secret_file: "./secret"
  publish_interval_seconds: 60
  min_instances_for_correlation: 1
  correlation_window_seconds: 300
  gc_interval_seconds: 600
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error when min_instances_for_correlation < 2")
	}
}

func TestLoad_FederationValidConfig(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  federation: true
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
federation:
  peers_file: "./peers.yaml"
  signing_key_file: "./key.pem"
  shared_secret_file: "./secret"
  publish_interval_seconds: 60
  min_instances_for_correlation: 2
  correlation_window_seconds: 300
  gc_interval_seconds: 600
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected a valid federation config to pass, got: %v", err)
	}
	if cfg.Federation.PeersFile != "./peers.yaml" {
		t.Errorf("unexpected Federation.PeersFile: %q", cfg.Federation.PeersFile)
	}
	if cfg.Federation.MinInstancesForCorrelation != 2 {
		t.Errorf("unexpected Federation.MinInstancesForCorrelation: %d", cfg.Federation.MinInstancesForCorrelation)
	}
}

func TestConfig_Validate_MLScoreEnabledRequiresPositiveThreshold(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 0
    min_calls: 5
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when ml_score is enabled with a non-positive score_threshold")
	}
}

func TestConfig_Validate_MLScoreEnabledRequiresPositiveMinCalls(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 3.0
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when ml_score is enabled with a non-positive min_calls")
	}
}

// TestConfig_Validate_MLScoreMinCallsBelowTwoRejected covers the gap
// MinCalls > 0 left open: at min_calls: 1 the floor is satisfied by a
// window that cannot produce an inter-arrival delta at all
// (interArrivalN == 0 for a single call), so that feature reads 0.0 -- its
// harmful-direction range extreme -- for a lone call no matter how the
// identity actually behaved. Against a baseline of 1.0s/1.2s spacings
// (mean 1.0909, floored stddev 0.15*1.0909 = 0.16364) that scores
// z = (0-1.0909)/0.16364 = -6.667, which sign-flips to +6.667 and blocks.
// 2 is the smallest window size at which every feature has a defined
// value, which is what MinCalls was for in the first place.
func TestConfig_Validate_MLScoreMinCallsBelowTwoRejected(t *testing.T) {
	mlScoreConfig := func(minCalls int) string {
		return fmt.Sprintf(`
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: %d
audit:
  output: stdout
`, minCalls)
	}

	_, err := config.Load(writeTemp(t, mlScoreConfig(1)))
	if err == nil {
		t.Fatal("expected error when ml_score.min_calls is 1")
	}
	if !strings.Contains(err.Error(), "must be >= 2") {
		t.Errorf("expected the error to say min_calls must be >= 2, got: %v", err)
	}

	cfg, err := config.Load(writeTemp(t, mlScoreConfig(2)))
	if err != nil {
		t.Fatalf("expected ml_score.min_calls: 2 to pass validation, got: %v", err)
	}
	if cfg.Anomaly.MLScore.MinCalls != 2 {
		t.Errorf("unexpected Anomaly.MLScore.MinCalls: %d", cfg.Anomaly.MLScore.MinCalls)
	}
}

func TestConfig_Validate_AutoBlockRequiresMLScoreEnabled(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: false
  auto_block:
    enabled: true
    score_threshold: 3.0
    block_duration_seconds: 300
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when auto_block is enabled but ml_score is not")
	}
}

func TestConfig_Validate_AutoBlockRequiresPositiveThresholdAndDuration(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 5
  auto_block:
    enabled: true
    score_threshold: 0
    block_duration_seconds: 0
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when auto_block is enabled with a non-positive score_threshold or block_duration_seconds")
	}
}

func TestConfig_Validate_AutoBlockThresholdBelowMLScoreThresholdRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 8.0
    min_calls: 5
  auto_block:
    enabled: true
    score_threshold: 3.0
    block_duration_seconds: 300
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when auto_block.score_threshold is lower than ml_score.score_threshold")
	}
}

// TestConfig_Validate_AutoBlockDurationVsGCInterval covers the invariant
// anomaly/usecase.gc relies on to skip any blocked-identity special case:
// a block longer than 2x the GC interval would have its frozen baseline
// evicted partway through, silently resetting it.
func TestConfig_Validate_AutoBlockDurationVsGCInterval(t *testing.T) {
	cfgYAML := func(blockDuration int) string {
		return fmt.Sprintf(`
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  gc_interval_seconds: 600
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 5
  auto_block:
    enabled: true
    score_threshold: 4.0
    block_duration_seconds: %d
audit:
  output: stdout
`, blockDuration)
	}

	// 1800s exceeds 2x600s: GC would evict the frozen baseline mid-block.
	if _, err := config.Load(writeTemp(t, cfgYAML(1800))); err == nil {
		t.Error("expected error when auto_block.block_duration_seconds exceeds 2x anomaly.gc_interval_seconds")
	} else if !strings.Contains(err.Error(), "garbage-collected mid-block") {
		t.Errorf("unexpected error for block_duration_seconds 1800 vs gc_interval_seconds 600: %v", err)
	}

	// 300s is the shipped example config's pairing, well within 2x600s.
	if _, err := config.Load(writeTemp(t, cfgYAML(300))); err != nil {
		t.Errorf("expected the shipped 300s/600s pairing to pass, got: %v", err)
	}
}

// TestConfig_Validate_OmittedGCIntervalDefaultsBeforeAutoBlockCheck is the
// regression gate for the bypass in the check above: gc_interval_seconds is
// documented as optional, and while it was left at its zero value through
// validation the whole cross-check was skipped -- cmd/wardline/main.go then
// applied its own 600s default at wiring time, so a 3600s block duration was
// silently accepted at 6x the effective GC interval. validate() now applies
// the default itself, before the check that reads it.
func TestConfig_Validate_OmittedGCIntervalDefaultsBeforeAutoBlockCheck(t *testing.T) {
	cfgYAML := func(blockDuration int) string {
		return fmt.Sprintf(`
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 5
  auto_block:
    enabled: true
    score_threshold: 4.0
    block_duration_seconds: %d
audit:
  output: stdout
`, blockDuration)
	}

	if _, err := config.Load(writeTemp(t, cfgYAML(3600))); err == nil {
		t.Error("expected block_duration_seconds 3600 to be rejected against the defaulted 600s gc_interval_seconds")
	} else if !strings.Contains(err.Error(), "garbage-collected mid-block") {
		t.Errorf("unexpected error for an omitted gc_interval_seconds with block_duration_seconds 3600: %v", err)
	}

	cfg, err := config.Load(writeTemp(t, cfgYAML(300)))
	if err != nil {
		t.Fatalf("expected an omitted gc_interval_seconds with block_duration_seconds 300 to pass, got: %v", err)
	}
	if cfg.Anomaly.GCIntervalSeconds != 600 {
		t.Errorf("expected an omitted gc_interval_seconds to read back as the 600s default, got %d", cfg.Anomaly.GCIntervalSeconds)
	}
}

func TestConfig_Validate_ValidMLScoreAndAutoBlockConfig(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
features:
  anomaly_detection: true
anomaly:
  output: "./anomaly.jsonl"
  window_seconds: 60
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 5
  auto_block:
    enabled: true
    score_threshold: 4.0
    block_duration_seconds: 300
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected a valid ml_score/auto_block config to pass, got: %v", err)
	}
	if cfg.Anomaly.MLScore.ScoreThreshold != 3.0 {
		t.Errorf("unexpected Anomaly.MLScore.ScoreThreshold: %v", cfg.Anomaly.MLScore.ScoreThreshold)
	}
	if cfg.Anomaly.MLScore.MinCalls != 5 {
		t.Errorf("unexpected Anomaly.MLScore.MinCalls: %d", cfg.Anomaly.MLScore.MinCalls)
	}
	if cfg.Anomaly.AutoBlock.BlockDurationSeconds != 300 {
		t.Errorf("unexpected Anomaly.AutoBlock.BlockDurationSeconds: %d", cfg.Anomaly.AutoBlock.BlockDurationSeconds)
	}
}

func TestValidate_ScimRequiresBearerTokenEnv(t *testing.T) {
	baseYAML := `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  scim: true
`
	if _, err := config.Load(writeTemp(t, baseYAML)); err == nil {
		t.Fatal("expected validation error for scim with no bearer_token_env")
	}

	validYAML := baseYAML + `
scim:
  bearer_token_env: "WARDLINE_SCIM_TOKEN"
`
	if _, err := config.Load(writeTemp(t, validYAML)); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	persistWithoutPostgresYAML := baseYAML + `
scim:
  bearer_token_env: "WARDLINE_SCIM_TOKEN"
  persist_postgres: true
`
	if _, err := config.Load(writeTemp(t, persistWithoutPostgresYAML)); err == nil {
		t.Fatal("expected validation error for scim.persist_postgres without features.postgres_storage")
	}
}

func TestLoad_AccessTokenTTLDefaultsToFifteenMinutesWhenZero(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Credential.AccessTokenTTLSeconds != 900 {
		t.Errorf("expected access_token_ttl_seconds to default to 900, got %d", cfg.Credential.AccessTokenTTLSeconds)
	}
	if cfg.Credential.RefreshTokenTTLSeconds != 86400 {
		t.Errorf("expected refresh_token_ttl_seconds to default to 86400, got %d", cfg.Credential.RefreshTokenTTLSeconds)
	}
}

func TestLoad_AccessAndRefreshTokenTTLRoundTripWhenSet(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  access_token_ttl_seconds: 60
  refresh_token_ttl_seconds: 3600
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Credential.AccessTokenTTLSeconds != 60 {
		t.Errorf("expected access_token_ttl_seconds to round-trip to 60, got %d", cfg.Credential.AccessTokenTTLSeconds)
	}
	if cfg.Credential.RefreshTokenTTLSeconds != 3600 {
		t.Errorf("expected refresh_token_ttl_seconds to round-trip to 3600, got %d", cfg.Credential.RefreshTokenTTLSeconds)
	}
}

func TestLoad_NegativeAccessTokenTTLIsRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  access_token_ttl_seconds: -1
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error for a negative access_token_ttl_seconds")
	}
}

func TestLoad_NegativeRefreshTokenTTLIsRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: "creds.yaml"
  refresh_token_ttl_seconds: -1
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error for a negative refresh_token_ttl_seconds")
	}
}

func TestLoad_AuditRetentionDaysOnStdoutRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
  retention_days: 30
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error for audit.retention_days set while audit.output is stdout")
	}
}

func TestLoad_JobCostBudgetBlockParses(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
features:
  job_cost_budget: true
job_cost_budget:
  ceiling: 500
  tool_costs:
    llm_call: 50
  default_cost: 2
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.JobCostBudget.Ceiling != 500 {
		t.Errorf("unexpected ceiling: %+v", cfg.JobCostBudget)
	}
	if cfg.JobCostBudget.ToolCosts["llm_call"] != 50 {
		t.Errorf("unexpected tool_costs: %+v", cfg.JobCostBudget.ToolCosts)
	}
	if cfg.JobCostBudget.DefaultCost != 2 {
		t.Errorf("unexpected default_cost: %+v", cfg.JobCostBudget)
	}
}

func TestLoad_JobCostBudgetBlockAbsentIsZeroValue(t *testing.T) {
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
	if cfg.JobCostBudget.Ceiling != 0 || cfg.JobCostBudget.ToolCosts != nil {
		t.Errorf("expected zero-value JobCostBudgetConfig, got %+v", cfg.JobCostBudget)
	}
}

func TestLoad_AnomalyRetentionDaysOnStdoutRejected(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
anomaly:
  output: stdout
  retention_days: 30
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error for anomaly.retention_days set while anomaly.output is stdout")
	}
}

func TestLoad_LogRetentionFlagRequiresARetentionDaysValue(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: "./audit.jsonl"
features:
  log_retention: true
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error when features.log_retention is on but no retention_days is set")
	}
}

func TestLoad_LogRetentionValidConfig(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: "./audit.jsonl"
  retention_days: 30
features:
  log_retention: true
retention:
  check_interval_seconds: 3600
`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("unexpected error for a valid log_retention config: %v", err)
	}
}

func TestLoad_ScheduledExportRequiresIntervalAndOutputDir(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: "./audit.jsonl"
features:
  compliance_scheduled_export: true
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected validation error when compliance_scheduled_export is on but interval/output_dir are unset")
	}
	if !strings.Contains(err.Error(), "scheduled_export_interval_seconds") || !strings.Contains(err.Error(), "scheduled_export_output_dir") {
		t.Errorf("expected the error to name both missing fields, got: %v", err)
	}
}

func TestLoad_ScheduledExportRequiresQueryableAuditTrail(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: stdout
features:
  compliance_scheduled_export: true
compliance:
  scheduled_export_interval_seconds: 3600
  scheduled_export_output_dir: "./evidence"
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected validation error when compliance_scheduled_export is on but audit.output is stdout")
	}
}

func TestLoad_ScheduledExportValidConfig(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9090"
policy_file: "policy.yaml"
audit:
  output: "./audit.jsonl"
features:
  compliance_scheduled_export: true
compliance:
  scheduled_export_interval_seconds: 3600
  scheduled_export_output_dir: "./evidence"
  signing_key_file: "./signing-key.pem"
`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("unexpected error for a valid compliance_scheduled_export config: %v", err)
	}
}

func TestLoad_TaintBlockParses(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
features:
  taint_tracking: true
taint:
  untrusted_sources:
    - web_fetch
    - http_get
  declassify_sources:
    - human_approve
  ttl_seconds: 120
  session_window_seconds: 60
  session_header: "X-Session"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Taint.UntrustedSources; len(got) != 2 || got[0] != "web_fetch" || got[1] != "http_get" {
		t.Errorf("unexpected untrusted_sources: %+v", got)
	}
	if got := cfg.Taint.DeclassifySources; len(got) != 1 || got[0] != "human_approve" {
		t.Errorf("unexpected declassify_sources: %+v", got)
	}
	if cfg.Taint.TTLSeconds != 120 || cfg.Taint.SessionWindowSeconds != 60 || cfg.Taint.SessionHeader != "X-Session" {
		t.Errorf("unexpected taint numeric/header fields: %+v", cfg.Taint)
	}
}

func TestLoad_TaintBlockAbsentIsZeroValue(t *testing.T) {
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
	if cfg.Taint.UntrustedSources != nil || cfg.Taint.TTLSeconds != 0 {
		t.Errorf("expected zero-value TaintConfig when the block is absent, got %+v", cfg.Taint)
	}
}

func TestLoad_ApprovalBlockParses(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
features:
  approval_workflow: true
approval:
  grant_ttl_seconds: 600
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Approval.GrantTTLSeconds != 600 {
		t.Errorf("unexpected grant_ttl_seconds: %d, expected 600", cfg.Approval.GrantTTLSeconds)
	}
}

func TestLoad_ApprovalBlockAbsentIsZeroValue(t *testing.T) {
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
	if cfg.Approval.GrantTTLSeconds != 0 {
		t.Errorf("expected zero-value ApprovalConfig when the block is absent, got %+v", cfg.Approval)
	}
}

func TestLoad_JobBudgetBlockParses(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
features:
  job_budget: true
job_budget:
  requests_per_job: 250
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.JobBudget.RequestsPerJob != 250 {
		t.Errorf("unexpected requests_per_job: %+v", cfg.JobBudget)
	}
}

func TestLoad_JobBudgetBlockAbsentIsZeroValue(t *testing.T) {
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
	if cfg.JobBudget.RequestsPerJob != 0 {
		t.Errorf("expected zero-value JobBudgetConfig, got %+v", cfg.JobBudget)
	}
}
