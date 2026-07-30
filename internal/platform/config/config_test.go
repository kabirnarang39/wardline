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
