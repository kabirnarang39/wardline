package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuditConfig configures where audit entries are recorded. Output is
// used unless postgres_storage is on, in which case PostgresDSN is used
// instead — see Config.validate() and postgres_storage's flag gating.
type AuditConfig struct {
	Output      string `yaml:"output"`       // "stdout" or a file path
	PostgresDSN string `yaml:"postgres_dsn"` // only used when features.postgres_storage is true

	// RetentionDays, when > 0, is how many days of audit history
	// features.log_retention's periodic job keeps before purging older
	// entries -- 0 (the default) means keep forever, preserving every
	// existing deployment's behavior exactly. Meaningless (and rejected
	// by validate()) when Output is "stdout": nothing durable exists
	// there to retain or purge.
	RetentionDays int `yaml:"retention_days"`
}

// TaintConfig configures integrity taint tracking. Only meaningful when the
// taint_tracking feature flag is on. UntrustedSources are tool names whose
// invocation taints the calling (tenant, identity, session); DeclassifySources
// clear taint. The numeric fields default (see taint/domain) when unset.
type TaintConfig struct {
	UntrustedSources     []string `yaml:"untrusted_sources"`
	DeclassifySources    []string `yaml:"declassify_sources"`
	TTLSeconds           int      `yaml:"ttl_seconds"`
	SessionWindowSeconds int      `yaml:"session_window_seconds"`
	SessionHeader        string   `yaml:"session_header"`
}

// ApprovalConfig configures request approvals. Only meaningful when the
// approval_workflow feature flag is on. The numeric field defaults
// (see approval/domain) when unset.
type ApprovalConfig struct {
	GrantTTLSeconds int `yaml:"grant_ttl_seconds"`
}

// JobBudgetConfig configures per-job request limits. Only meaningful when the
// job_budget feature flag is on.
type JobBudgetConfig struct {
	RequestsPerJob int `yaml:"requests_per_job"`

	// SessionWindowSeconds is the fallback session-window width used when
	// a call carries no X-Wardline-Session header -- mirrors taint's own
	// session_window_seconds, own knob so job-budget's window stays
	// configurable independently of taint_tracking being on.
	SessionWindowSeconds int `yaml:"session_window_seconds"`
}

// JobCostBudgetConfig configures per-job cost budgets. Only meaningful when the
// job_cost_budget feature flag is on.
type JobCostBudgetConfig struct {
	Ceiling     int            `yaml:"ceiling"`
	ToolCosts   map[string]int `yaml:"tool_costs"`
	DefaultCost int            `yaml:"default_cost"`

	// SessionWindowSeconds mirrors JobBudgetConfig.SessionWindowSeconds
	// exactly, own knob for cost-budget's own fallback window.
	SessionWindowSeconds int `yaml:"session_window_seconds"`
}

// BudgetConfig configures the per-identity rate limiter. Only validated
// (and only meaningful) when the budget_enforcement feature flag is on.
// Tenants holds optional per-tenant overrides of the global default above,
// keyed by tenant name. A tenant absent from this map uses the global
// default unchanged — so a deployment that never sets budget.tenants
// behaves byte-for-byte identically to before per-tenant overrides existed.
type BudgetConfig struct {
	RequestsPerWindow int `yaml:"requests_per_window"`
	WindowSeconds     int `yaml:"window_seconds"`
	// Tenants is recursively self-typed (it reuses BudgetConfig), but only
	// one level deep is ever wired up (see cmd/wardline/main.go) -- a
	// nested tenants.acme.tenants.* entry is syntactically valid YAML that
	// is silently ignored. Do not nest.
	Tenants map[string]BudgetConfig `yaml:"tenants"`
	// Tools holds optional per-tool overrides, keyed by tool name -- same
	// recursively-self-typed shape and same "only one level deep is wired
	// up, do not nest" caveat as Tenants above.
	Tools map[string]BudgetConfig `yaml:"tools"`
}

// maxBudgetWindowSeconds bounds budget.window_seconds to 24h, a reasonable
// ceiling for a rate-limit window. It exists to catch config mistakes (a
// pasted-in millisecond/nanosecond figure) before
// time.Duration(WindowSeconds)*time.Second in cmd/wardline/main.go turns it
// into an implausibly large or overflowing duration.
const maxBudgetWindowSeconds = 86400

// defaultTracingServiceName is used when tracing is enabled but the
// operator didn't set tracing.service_name.
const defaultTracingServiceName = "wardline"

// defaultAnomalyGCIntervalSeconds is the single source of truth for
// anomaly.gc_interval_seconds' default. It has to be applied here, in
// validate(), rather than only at wiring time in cmd/wardline/main.go:
// the auto_block/GC-interval cross-validation below runs before any
// runtime default would, so an omitted gc_interval_seconds used to read
// as 0 and skip that check entirely.
const defaultAnomalyGCIntervalSeconds = 600

// defaultAccessTokenTTLSeconds preserves this project's original fixed
// 15-minute access-token lifetime as the default once the field became
// operator-configurable.
const defaultAccessTokenTTLSeconds = 900

// defaultRefreshTokenTTLSeconds is a reasonable default lifetime for a
// refresh token: long enough to meaningfully reduce re-bootstrap
// frequency, short enough that a leaked-but-unused refresh token has a
// bounded blast radius.
const defaultRefreshTokenTTLSeconds = 86400

// TracingConfig configures OTLP/HTTP span export. Only validated (and
// only meaningful) when the otel_tracing feature flag is on.
type TracingConfig struct {
	OTLPEndpoint string `yaml:"otlp_endpoint"` // host:port, no scheme
	ServiceName  string `yaml:"service_name"`  // defaults to "wardline"
}

// OIDCConfig configures the OIDC SSO bootstrap adapter. Only validated
// (and only meaningful) when credential.bootstrap_source is "oidc".
type OIDCConfig struct {
	Issuer        string `yaml:"issuer"`
	JWKSURI       string `yaml:"jwks_uri"`
	Audience      string `yaml:"audience"`
	IdentityClaim string `yaml:"identity_claim"` // defaults to "sub"
	TenantClaim   string `yaml:"tenant_claim"`   // defaults to "tenant"
}

// MTLSConfig configures the mTLS/SPIFFE bootstrap adapter. Only
// validated (and only meaningful) when credential.bootstrap_source is
// "mtls". Wardline never terminates TLS or parses X.509 itself -- Header
// names the HTTP header a terminating mTLS proxy/mesh (Envoy, Istio,
// nginx with ssl_verify_client, ...) must set to the caller's
// already-verified SPIFFE ID after successfully completing the mTLS
// handshake. No default value: an operator must name a header their own
// ingress/mesh actually sets (and strips from any client-supplied
// value) -- a well-known default would invite accidentally trusting a
// header nobody configured their proxy to guarantee.
type MTLSConfig struct {
	Header string `yaml:"header"`
}

// CredentialConfig configures credential issuance. Only validated (and
// only meaningful) when the credential_issuance feature flag is on.
type CredentialConfig struct {
	IdentitiesFile string `yaml:"identities_file"`

	// SigningKeyFile optionally points at a PEM-encoded RSA private key
	// (PKCS1 or PKCS8) every replica loads identically -- required for
	// credential issuance to work correctly across more than one
	// replica (see README.md "HA deployment"). Empty (the default)
	// preserves the existing single-process generate-fresh-in-process
	// behavior. Presence is not checked here (matching every other
	// optional file-based config field in this struct) -- the real
	// load-and-parse happens at wardline serve/validate-config
	// construction time via credentialadapter.NewJWTIssuerVerifier.
	SigningKeyFile string `yaml:"signing_key_file"`

	// PreviousSigningKeyFiles optionally lists PEM RSA private keys whose
	// public halves are accepted for VERIFICATION ONLY -- the key-rotation
	// window. An operator rotates by generating a new key, moving the old
	// signing_key_file path into this list, pointing signing_key_file at
	// the new key, and redeploying: tokens signed under the old key keep
	// verifying (up to their own TTL) while new tokens use the new key.
	// Once the old key's longest-lived outstanding token has expired
	// (bounded by access_token_ttl_seconds/refresh_token_ttl_seconds),
	// drop it from this list. Empty (the default) is the no-rotation-in-
	// progress state. See README.md "Credential issuance".
	PreviousSigningKeyFiles []string `yaml:"previous_signing_key_files"`

	// BootstrapSource selects which Bootstrapper adapter authenticates a
	// credential exchange: "presharedsecret" (default, credentials.yaml
	// via IdentitiesFile), "oidc" (OIDC ID token via OIDC below), or
	// "mtls" (already-verified SPIFFE ID via a trusted header, see MTLS
	// below).
	BootstrapSource string     `yaml:"bootstrap_source"`
	OIDC            OIDCConfig `yaml:"oidc"`
	MTLS            MTLSConfig `yaml:"mtls"`

	// AccessTokenTTLSeconds is how long an issued access-token JWT is
	// valid for. 0 (the default) uses defaultAccessTokenTTLSeconds
	// (900s / 15m), preserving every existing deployment's behavior
	// exactly with no config change required. Negative is a hard
	// validation error, distinguishing "operator left it unset" from
	// "operator typo'd a negative number" -- unlike anomaly.gc_interval_seconds'
	// <=0-silently-defaults convention elsewhere in this file.
	AccessTokenTTLSeconds int `yaml:"access_token_ttl_seconds"`

	// RefreshTokenTTLSeconds is how long an issued refresh token remains
	// redeemable. 0 (the default) uses defaultRefreshTokenTTLSeconds
	// (86400s / 24h). Same negative-is-an-error rule as
	// AccessTokenTTLSeconds above. No requirement that this exceed
	// AccessTokenTTLSeconds is enforced -- an operator setting it
	// shorter is unusual but harmless (refresh just becomes useless
	// before the access token even expires), not worth a hard failure.
	RefreshTokenTTLSeconds int `yaml:"refresh_token_ttl_seconds"`
}

// RBACConfig configures Kubernetes-shaped RBAC. Only validated (and only
// meaningful) when the rbac feature flag is on.
type RBACConfig struct {
	ConfigFile string `yaml:"config_file"`
}

// ScimConfig configures the SCIM 2.0 provisioning API. Only validated
// (and only meaningful) when the scim feature flag is on.
type ScimConfig struct {
	BearerTokenEnv  string `yaml:"bearer_token_env"`
	PersistPostgres bool   `yaml:"persist_postgres"`
}

// RateSpikeConfig configures the rate-spike heuristic. Shares
// AnomalyConfig.WindowSeconds with DenyRateSpikeConfig: both are
// volumetric counts over the same identity traffic, so one trailing
// window per identity is deliberate rather than two independently-sized
// ones (see README.md "Anomaly detection").
type RateSpikeConfig struct {
	Enabled    bool    `yaml:"enabled"`
	Multiplier float64 `yaml:"rate_multiplier"`
	MinCalls   int     `yaml:"min_calls"`
}

// NovelToolConfig configures the novel-tool heuristic. No numeric
// parameters -- it has no threshold, only an on/off switch.
type NovelToolConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DenyRateSpikeConfig configures the deny-rate-spike heuristic.
type DenyRateSpikeConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Threshold float64 `yaml:"threshold"`
	MinCalls  int     `yaml:"min_calls"`
}

// MLScoreConfig configures the combined-z-score ML detector.
type MLScoreConfig struct {
	Enabled        bool    `yaml:"enabled"`
	ScoreThreshold float64 `yaml:"score_threshold"`
	MinCalls       int     `yaml:"min_calls"`
}

// AutoBlockConfig configures whether an ml_score or drift_detection
// anomaly also blocks the offending identity for a time-bounded window.
type AutoBlockConfig struct {
	Enabled              bool    `yaml:"enabled"`
	ScoreThreshold       float64 `yaml:"score_threshold"`
	BlockDurationSeconds int     `yaml:"block_duration_seconds"`
}

// DriftConfig configures the drift-detection heuristic (a CUSUM control
// chart over call_rate and tool_diversity) -- see anomaly/
// domain.DriftConfig's doc comment for the statistics. K and H are both
// in units of the scored feature's own baseline standard deviation.
type DriftConfig struct {
	Enabled          bool    `yaml:"enabled"`
	K                float64 `yaml:"k"`
	H                float64 `yaml:"h"`
	MinCalls         int     `yaml:"min_calls"`
	HJitterFraction  float64 `yaml:"h_jitter_fraction"`
	JitterSecretFile string  `yaml:"jitter_secret_file"`
}

// TenantAnomalyConfig configures tenant-aggregate rate detection -- see
// anomaly/domain.TenantAnomalyConfig's doc comment.
type TenantAnomalyConfig struct {
	Enabled        bool    `yaml:"enabled"`
	RateMultiplier float64 `yaml:"rate_multiplier"`
	MinCalls       int     `yaml:"min_calls"`
}

// IdentityChurnConfig configures identity-churn detection -- see
// anomaly/domain.IdentityChurnConfig's doc comment.
type IdentityChurnConfig struct {
	Enabled          bool    `yaml:"enabled"`
	RateMultiplier   float64 `yaml:"rate_multiplier"`
	MinNewIdentities int     `yaml:"min_new_identities"`
}

// AnomalyConfig configures anomaly detection. Only validated (and only
// meaningful) when the anomaly_detection feature flag is on.
type AnomalyConfig struct {
	Output            string              `yaml:"output"`
	BufferCapacity    int                 `yaml:"buffer_capacity"`
	GCIntervalSeconds int                 `yaml:"gc_interval_seconds"`
	WindowSeconds     int                 `yaml:"window_seconds"`
	RateSpike         RateSpikeConfig     `yaml:"rate_spike"`
	NovelTool         NovelToolConfig     `yaml:"novel_tool"`
	DenyRateSpike     DenyRateSpikeConfig `yaml:"deny_rate_spike"`
	MLScore           MLScoreConfig       `yaml:"ml_score"`
	AutoBlock         AutoBlockConfig     `yaml:"auto_block"`
	Drift             DriftConfig         `yaml:"drift_detection"`
	TenantAnomaly     TenantAnomalyConfig `yaml:"tenant_anomaly"`
	IdentityChurn     IdentityChurnConfig `yaml:"identity_churn"`

	// RetentionDays mirrors AuditConfig.RetentionDays -- see its doc
	// comment. This is the anomaly LOG's own retention (the JSONL/
	// Postgres record of past detections), unrelated to
	// GCIntervalSeconds above, which governs the separate in-memory
	// behavioral baseline's own eviction, not the durable log.
	RetentionDays int `yaml:"retention_days"`
}

// ComplianceConfig configures the periodic scheduled-export background
// job. Only validated (and only meaningful) when the
// compliance_scheduled_export feature flag is on.
type ComplianceConfig struct {
	ScheduledExportIntervalSeconds int `yaml:"scheduled_export_interval_seconds"`
	// ScheduledExportOutputDir is where each tick's bundle is written
	// (evidence-<from>-<to>.tar.gz inside it) -- required when the flag
	// is on, matching every other required-when-flag-on field in this
	// file.
	ScheduledExportOutputDir string `yaml:"scheduled_export_output_dir"`
	// SigningKeyFile is optional -- the same PEM path shape
	// export-evidence -sign-key expects, reused for every scheduled run
	// so an operator doesn't need to touch the filesystem each cycle.
	// "" (the default) produces unsigned scheduled bundles.
	SigningKeyFile string `yaml:"signing_key_file"`
}

// RetentionConfig configures the periodic log-retention background job.
// Only validated (and only meaningful) when the log_retention feature
// flag is on. A single shared interval governs both the audit and
// anomaly retention checks (whichever of AuditConfig.RetentionDays/
// AnomalyConfig.RetentionDays is non-zero runs on this cadence) --
// simpler than two independently-configurable tickers for what's
// operationally one "how often does housekeeping run" knob.
type RetentionConfig struct {
	CheckIntervalSeconds int `yaml:"check_interval_seconds"`
}

// FederationConfig configures cross-instance anomaly correlation. Only
// validated (and only meaningful) when the federation feature flag is
// on, which itself requires anomaly_detection also be on.
type FederationConfig struct {
	// InstanceID overrides this process's federation instance ID.
	// Optional -- when empty (the default), main.go derives it from
	// os.Hostname() instead. os.Hostname() alone is only unique per host,
	// not per process: any deployment topology that runs more than one
	// Wardline process on the same host (bare-metal/VM multi-instance,
	// or two instances sharing a network namespace) would otherwise have
	// every instance report the identical instance ID, which silently
	// caps the Correlator's distinct-instance count at 1 and makes
	// cross-instance correlation impossible to ever trip -- this override
	// is the operator's escape hatch for that case.
	InstanceID                 string `yaml:"instance_id"`
	PeersFile                  string `yaml:"peers_file"`
	SigningKeyFile             string `yaml:"signing_key_file"`
	SharedSecretFile           string `yaml:"shared_secret_file"`
	PublishIntervalSeconds     int    `yaml:"publish_interval_seconds"`
	MinInstancesForCorrelation int    `yaml:"min_instances_for_correlation"`
	CorrelationWindowSeconds   int    `yaml:"correlation_window_seconds"`
	GCIntervalSeconds          int    `yaml:"gc_interval_seconds"`
}

// Config is Wardline's top-level operator configuration. Features holds
// flag toggles for capabilities added after v0.1 — budget_enforcement and
// otel_tracing are the two real ones so far; internal/platform/flags
// reads this map to decide whether a flagged feature is on.
type Config struct {
	Listen     string `yaml:"listen"`
	Upstream   string `yaml:"upstream"`
	PolicyFile string `yaml:"policy_file"`

	// GRPCListen / GRPCUpstream configure the gRPC transport (feature
	// grpc_transport). GRPCListen is a host:port to accept gRPC on;
	// GRPCUpstream is the upstream gRPC target (host:port, or any
	// grpc.NewClient target). Both required when grpc_transport is on,
	// ignored otherwise. Unlike Upstream these are plain gRPC targets, not
	// URLs -- the gRPC transport is plaintext to the upstream today (TLS to
	// upstream is a deliberate follow-up).
	GRPCListen   string `yaml:"grpc_listen"`
	GRPCUpstream string `yaml:"grpc_upstream"`
	// GRPCUpstreamTLS dials the gRPC upstream over TLS (verified against
	// the host's system root pool, server name from GRPCUpstream) instead
	// of plaintext. Default false preserves the plaintext-to-mesh behavior;
	// set true when Wardline talks directly to a TLS-terminating upstream.
	GRPCUpstreamTLS bool                `yaml:"grpc_upstream_tls"`
	PolicyBackend   string              `yaml:"policy_backend"` // "yaml" (default), "opa", or "cedar"
	Audit           AuditConfig         `yaml:"audit"`
	Budget          BudgetConfig        `yaml:"budget"`
	Tracing         TracingConfig       `yaml:"tracing"`
	Credential      CredentialConfig    `yaml:"credential"`
	RBAC            RBACConfig          `yaml:"rbac"`
	Scim            ScimConfig          `yaml:"scim"`
	Anomaly         AnomalyConfig       `yaml:"anomaly"`
	Federation      FederationConfig    `yaml:"federation"`
	Compliance      ComplianceConfig    `yaml:"compliance"`
	Retention       RetentionConfig     `yaml:"retention"`
	Taint           TaintConfig         `yaml:"taint"`
	Approval        ApprovalConfig      `yaml:"approval"`
	JobBudget       JobBudgetConfig     `yaml:"job_budget"`
	JobCostBudget   JobCostBudgetConfig `yaml:"job_cost_budget"`
	Features        map[string]bool     `yaml:"features"`

	// ShutdownDelaySeconds, when > 0, is how long wardline keeps serving
	// requests normally after receiving SIGTERM/SIGINT before it begins
	// its own drain sequence (marking /readyz unready, then
	// srv.Shutdown). This is an in-process substitute for a Kubernetes
	// preStop hook: it buys the same real-world propagation time (for
	// kube-proxy/the Endpoints controller to remove this pod from
	// Service routing before it stops accepting connections) without
	// depending on a shell existing in the container -- Wardline's own
	// published image is distroless and has none. Zero (the default)
	// preserves today's shutdown behavior exactly: draining begins the
	// instant the signal arrives.
	ShutdownDelaySeconds int `yaml:"shutdown_delay_seconds"`

	// UpstreamURL is the parsed and validated form of Upstream, populated by
	// validate(). Callers (cmd/wardline/main.go) should use this instead of
	// re-parsing Upstream themselves.
	UpstreamURL *url.URL `yaml:"-"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := ParseBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// ParseBytes validates and parses config YAML content already in
// memory, the half of Load's work that doesn't need a filesystem path
// -- extracted so a caller writing NEW config content (the dashboard's
// Budget editor, see WriteBudgetSection) can validate the exact bytes
// about to be persisted BEFORE writing anything, the same
// validate-before-persist discipline policyadapter.WriteFile/ParseYAML
// already established for the Policy editor.
func ParseBytes(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	var problems []string
	if c.Listen == "" {
		problems = append(problems, "listen must not be empty")
	}
	if c.Upstream == "" {
		problems = append(problems, "upstream must not be empty")
	} else if u, err := url.ParseRequestURI(c.Upstream); err != nil {
		problems = append(problems, fmt.Sprintf("upstream is not a valid URL: %v", err))
	} else if u.Scheme != "http" && u.Scheme != "https" {
		problems = append(problems, fmt.Sprintf("upstream must use http or https scheme, got %q", u.Scheme))
	} else if u.Host == "" {
		problems = append(problems, fmt.Sprintf("upstream must include a host, got %q", c.Upstream))
	} else {
		c.UpstreamURL = u
	}
	if c.PolicyFile == "" {
		problems = append(problems, "policy_file must not be empty")
	}
	if c.PolicyBackend == "" {
		c.PolicyBackend = "yaml"
	} else if c.PolicyBackend != "yaml" && c.PolicyBackend != "opa" && c.PolicyBackend != "cedar" {
		problems = append(problems, fmt.Sprintf(`policy_backend must be "yaml", "opa", or "cedar", got %q`, c.PolicyBackend))
	}
	if c.Features["grpc_transport"] {
		if c.GRPCListen == "" {
			problems = append(problems, "grpc_listen must not be empty when features.grpc_transport is true")
		}
		if c.GRPCUpstream == "" {
			problems = append(problems, "grpc_upstream must not be empty when features.grpc_transport is true")
		}
	}
	if c.Features["postgres_storage"] {
		if c.Audit.PostgresDSN == "" {
			problems = append(problems, "audit.postgres_dsn must not be empty when features.postgres_storage is true")
		}
	} else if c.Audit.Output == "" {
		problems = append(problems, "audit.output must not be empty (or set features.postgres_storage: true and audit.postgres_dsn instead)")
	}
	if c.Audit.RetentionDays < 0 {
		problems = append(problems, "audit.retention_days must be >= 0")
	} else if c.Audit.RetentionDays > 0 && c.Audit.Output == "stdout" {
		problems = append(problems, "audit.retention_days is meaningless when audit.output is stdout -- nothing durable exists there to retain or purge")
	}
	if c.Features["log_retention"] {
		if c.Audit.RetentionDays <= 0 && c.Anomaly.RetentionDays <= 0 {
			problems = append(problems, "at least one of audit.retention_days/anomaly.retention_days must be > 0 when features.log_retention is true -- otherwise the job has nothing to do")
		}
		if c.Retention.CheckIntervalSeconds < 0 {
			problems = append(problems, "retention.check_interval_seconds must be >= 0")
		}
	}
	if c.Features["compliance_scheduled_export"] {
		if c.Compliance.ScheduledExportIntervalSeconds <= 0 {
			problems = append(problems, "compliance.scheduled_export_interval_seconds must be > 0 when features.compliance_scheduled_export is true")
		}
		if c.Compliance.ScheduledExportOutputDir == "" {
			problems = append(problems, "compliance.scheduled_export_output_dir must not be empty when features.compliance_scheduled_export is true")
		}
		if !c.Features["postgres_storage"] && c.Audit.Output == "stdout" {
			problems = append(problems, "compliance.scheduled_export requires audit.output to be a file path (or features.postgres_storage) -- the audit trail is not queryable when audit.output is stdout")
		}
	}
	if c.Features["budget_enforcement"] {
		if c.Budget.RequestsPerWindow <= 0 {
			problems = append(problems, "budget.requests_per_window must be > 0 when features.budget_enforcement is true")
		}
		if c.Budget.WindowSeconds <= 0 {
			problems = append(problems, "budget.window_seconds must be > 0 when features.budget_enforcement is true")
		} else if c.Budget.WindowSeconds > maxBudgetWindowSeconds {
			problems = append(problems, fmt.Sprintf("budget.window_seconds must be <= %d (24h) when features.budget_enforcement is true, got %d", maxBudgetWindowSeconds, c.Budget.WindowSeconds))
		}
		// Same two checks as the global default above, per tenant override.
		// An unvalidated 0 requests_per_window would silently deny every
		// request for that tenant forever; an unvalidated 0 window_seconds
		// would silently make the override a no-op (bucket resets every
		// call) -- both are footguns an operator gets no warning about
		// without this. Sorted for deterministic error ordering.
		tenantNames := make([]string, 0, len(c.Budget.Tenants))
		for name := range c.Budget.Tenants {
			tenantNames = append(tenantNames, name)
		}
		sort.Strings(tenantNames)
		for _, name := range tenantNames {
			t := c.Budget.Tenants[name]
			if name == "" {
				problems = append(problems, "budget.tenants must not have an empty-string tenant key")
			}
			if t.RequestsPerWindow <= 0 {
				problems = append(problems, fmt.Sprintf("budget.tenants.%s.requests_per_window must be > 0 when features.budget_enforcement is true", name))
			}
			if t.WindowSeconds <= 0 {
				problems = append(problems, fmt.Sprintf("budget.tenants.%s.window_seconds must be > 0 when features.budget_enforcement is true", name))
			} else if t.WindowSeconds > maxBudgetWindowSeconds {
				problems = append(problems, fmt.Sprintf("budget.tenants.%s.window_seconds must be <= %d (24h) when features.budget_enforcement is true, got %d", name, maxBudgetWindowSeconds, t.WindowSeconds))
			}
		}
		// Same validation, mirrored for per-tool overrides.
		toolNames := make([]string, 0, len(c.Budget.Tools))
		for name := range c.Budget.Tools {
			toolNames = append(toolNames, name)
		}
		sort.Strings(toolNames)
		for _, name := range toolNames {
			t := c.Budget.Tools[name]
			if name == "" {
				problems = append(problems, "budget.tools must not have an empty-string tool key")
			}
			if t.RequestsPerWindow <= 0 {
				problems = append(problems, fmt.Sprintf("budget.tools.%s.requests_per_window must be > 0 when features.budget_enforcement is true", name))
			}
			if t.WindowSeconds <= 0 {
				problems = append(problems, fmt.Sprintf("budget.tools.%s.window_seconds must be > 0 when features.budget_enforcement is true", name))
			} else if t.WindowSeconds > maxBudgetWindowSeconds {
				problems = append(problems, fmt.Sprintf("budget.tools.%s.window_seconds must be <= %d (24h) when features.budget_enforcement is true, got %d", name, maxBudgetWindowSeconds, t.WindowSeconds))
			}
		}
	}
	if c.Features["otel_tracing"] {
		if c.Tracing.OTLPEndpoint == "" {
			problems = append(problems, "tracing.otlp_endpoint must not be empty when features.otel_tracing is true")
		}
		if c.Tracing.ServiceName == "" {
			c.Tracing.ServiceName = defaultTracingServiceName
		}
	}
	if c.Features["credential_issuance"] {
		if c.Credential.IdentitiesFile == "" {
			problems = append(problems, "credential.identities_file must not be empty when features.credential_issuance is true")
		}
		if c.Credential.BootstrapSource == "" {
			c.Credential.BootstrapSource = "presharedsecret"
		} else if c.Credential.BootstrapSource != "presharedsecret" && c.Credential.BootstrapSource != "oidc" && c.Credential.BootstrapSource != "mtls" {
			problems = append(problems, fmt.Sprintf(`credential.bootstrap_source must be "presharedsecret", "oidc", or "mtls", got %q`, c.Credential.BootstrapSource))
		}
		if c.Credential.BootstrapSource == "oidc" {
			if c.Credential.OIDC.Issuer == "" || c.Credential.OIDC.JWKSURI == "" || c.Credential.OIDC.Audience == "" {
				problems = append(problems, "credential.oidc.issuer, jwks_uri, and audience must all be set when credential.bootstrap_source is \"oidc\"")
			}
			if c.Credential.OIDC.IdentityClaim == "" {
				c.Credential.OIDC.IdentityClaim = "sub"
			}
			if c.Credential.OIDC.TenantClaim == "" {
				c.Credential.OIDC.TenantClaim = "tenant"
			}
		}
		if c.Credential.BootstrapSource == "mtls" && c.Credential.MTLS.Header == "" {
			problems = append(problems, `credential.mtls.header must not be empty when credential.bootstrap_source is "mtls"`)
		}
		if c.Credential.AccessTokenTTLSeconds < 0 {
			problems = append(problems, "credential.access_token_ttl_seconds must be >= 0 (0 uses the default of 900s / 15m)")
		} else if c.Credential.AccessTokenTTLSeconds == 0 {
			c.Credential.AccessTokenTTLSeconds = defaultAccessTokenTTLSeconds
		}
		if c.Credential.RefreshTokenTTLSeconds < 0 {
			problems = append(problems, "credential.refresh_token_ttl_seconds must be >= 0 (0 uses the default of 86400s / 24h)")
		} else if c.Credential.RefreshTokenTTLSeconds == 0 {
			c.Credential.RefreshTokenTTLSeconds = defaultRefreshTokenTTLSeconds
		}
	}
	if c.Features["rbac"] && c.RBAC.ConfigFile == "" {
		problems = append(problems, "rbac.config_file must not be empty when features.rbac is true")
	}
	if c.Features["scim"] {
		if c.Scim.BearerTokenEnv == "" {
			problems = append(problems, "scim.bearer_token_env must not be empty when features.scim is true")
		}
		if c.Scim.PersistPostgres && !c.Features["postgres_storage"] {
			problems = append(problems, "features.postgres_storage must be true when scim.persist_postgres is true")
		}
	}
	if c.Anomaly.RetentionDays < 0 {
		problems = append(problems, "anomaly.retention_days must be >= 0")
	} else if c.Anomaly.RetentionDays > 0 && c.Anomaly.Output == "stdout" {
		problems = append(problems, "anomaly.retention_days is meaningless when anomaly.output is stdout -- nothing durable exists there to retain or purge")
	}
	if c.Features["anomaly_detection"] {
		if c.Anomaly.Output == "" {
			problems = append(problems, "anomaly.output must not be empty when features.anomaly_detection is true")
		}
		// Anomaly records carry their own schema (kind/detail, no latency or
		// trace fields) and would break every audit-log consumer's assumption
		// that Decision is one of Entry's six documented values. Sharing
		// "stdout" is fine and intended -- the two streams stay
		// distinguishable there -- but sharing a file silently interleaves
		// two schemas into one JSONL trail.
		if c.Anomaly.Output != "" && c.Anomaly.Output != "stdout" && c.Anomaly.Output == c.Audit.Output {
			problems = append(problems, fmt.Sprintf("anomaly.output must not be the same file as audit.output (both %q) — anomaly records use a different schema and would corrupt the audit trail", c.Anomaly.Output))
		}
		if c.Anomaly.WindowSeconds <= 0 {
			problems = append(problems, "anomaly.window_seconds must be > 0 when features.anomaly_detection is true")
		}
		if c.Anomaly.RateSpike.Enabled && c.Anomaly.RateSpike.Multiplier <= 0 {
			problems = append(problems, "anomaly.rate_spike.rate_multiplier must be > 0 when anomaly.rate_spike.enabled is true")
		}
		if c.Anomaly.RateSpike.Enabled && c.Anomaly.RateSpike.MinCalls <= 0 {
			problems = append(problems, "anomaly.rate_spike.min_calls must be > 0 when anomaly.rate_spike.enabled is true")
		}
		if c.Anomaly.DenyRateSpike.Enabled && (c.Anomaly.DenyRateSpike.Threshold <= 0 || c.Anomaly.DenyRateSpike.Threshold > 1) {
			problems = append(problems, "anomaly.deny_rate_spike.threshold must be in (0, 1] when anomaly.deny_rate_spike.enabled is true")
		}
		if c.Anomaly.DenyRateSpike.Enabled && c.Anomaly.DenyRateSpike.MinCalls <= 0 {
			problems = append(problems, "anomaly.deny_rate_spike.min_calls must be > 0 when anomaly.deny_rate_spike.enabled is true")
		}
		if c.Anomaly.MLScore.Enabled && c.Anomaly.MLScore.ScoreThreshold <= 0 {
			problems = append(problems, "anomaly.ml_score.score_threshold must be > 0 when anomaly.ml_score.enabled is true")
		}
		if c.Anomaly.MLScore.Enabled && c.Anomaly.MLScore.MinCalls < 2 {
			problems = append(problems, "anomaly.ml_score.min_calls must be >= 2 when anomaly.ml_score.enabled is true -- a 1-call window has no inter-arrival delta at all, which forces that feature to its harmful-direction range extreme regardless of behavior")
		}
		if c.Anomaly.Drift.Enabled {
			if !c.Anomaly.MLScore.Enabled {
				problems = append(problems, "anomaly.ml_score.enabled must be true when anomaly.drift_detection.enabled is true -- drift_detection reuses ml_score's own call_rate baseline instead of duplicating one")
			}
			if c.Anomaly.Drift.K <= 0 {
				problems = append(problems, "anomaly.drift_detection.k must be > 0 when anomaly.drift_detection.enabled is true")
			}
			if c.Anomaly.Drift.H <= c.Anomaly.Drift.K {
				problems = append(problems, "anomaly.drift_detection.h must be > anomaly.drift_detection.k -- a decision threshold at or below the allowance would alarm on ordinary noise, not a sustained drift")
			}
			if c.Anomaly.Drift.MinCalls <= 0 {
				problems = append(problems, "anomaly.drift_detection.min_calls must be > 0 when anomaly.drift_detection.enabled is true")
			}
			if c.Anomaly.Drift.HJitterFraction < 0 || c.Anomaly.Drift.HJitterFraction >= 1 {
				problems = append(problems, "anomaly.drift_detection.h_jitter_fraction must be in [0, 1) -- 1 or more could jitter h down to zero or below")
			}
			if c.Anomaly.Drift.HJitterFraction > 0 && c.Anomaly.Drift.JitterSecretFile == "" {
				problems = append(problems, "anomaly.drift_detection.jitter_secret_file must not be empty when anomaly.drift_detection.h_jitter_fraction > 0 -- without a secret the per-identity jitter is attacker-reproducible and provides no real uncertainty")
			}
		}
		if c.Anomaly.TenantAnomaly.Enabled {
			// Deliberately no dependency on rate_spike/ml_score being
			// enabled -- unlike drift_detection (which reuses ml_score's
			// baseline), tenant_anomaly keeps its own self-contained
			// aggregate baseline and is a legitimate standalone choice for
			// an operator who only cares about tenant-level coordinated
			// spikes, not per-identity behavior.
			if c.Anomaly.TenantAnomaly.RateMultiplier <= 0 {
				problems = append(problems, "anomaly.tenant_anomaly.rate_multiplier must be > 0 when anomaly.tenant_anomaly.enabled is true")
			}
			if c.Anomaly.TenantAnomaly.MinCalls <= 0 {
				problems = append(problems, "anomaly.tenant_anomaly.min_calls must be > 0 when anomaly.tenant_anomaly.enabled is true")
			}
		}
		if c.Anomaly.IdentityChurn.Enabled {
			// No dependency on any other heuristic being enabled --
			// same standalone reasoning as tenant_anomaly above:
			// identity_churn keeps its own self-contained aggregate
			// baseline, and an operator who only cares about disposable-
			// identity rotation bursts doesn't need to also run
			// per-identity heuristics for this to be meaningful.
			if c.Anomaly.IdentityChurn.RateMultiplier <= 0 {
				problems = append(problems, "anomaly.identity_churn.rate_multiplier must be > 0 when anomaly.identity_churn.enabled is true")
			}
			if c.Anomaly.IdentityChurn.MinNewIdentities <= 0 {
				problems = append(problems, "anomaly.identity_churn.min_new_identities must be > 0 when anomaly.identity_churn.enabled is true")
			}
		}
		if c.Anomaly.GCIntervalSeconds <= 0 {
			c.Anomaly.GCIntervalSeconds = defaultAnomalyGCIntervalSeconds
		}
		if c.Anomaly.AutoBlock.Enabled {
			if !c.Anomaly.MLScore.Enabled {
				problems = append(problems, "anomaly.ml_score.enabled must be true when anomaly.auto_block.enabled is true -- auto-block acts on ml_score's value")
			}
			if c.Anomaly.AutoBlock.ScoreThreshold <= 0 {
				problems = append(problems, "anomaly.auto_block.score_threshold must be > 0 when anomaly.auto_block.enabled is true")
			}
			if c.Anomaly.MLScore.Enabled && c.Anomaly.AutoBlock.ScoreThreshold < c.Anomaly.MLScore.ScoreThreshold {
				problems = append(problems, "anomaly.auto_block.score_threshold must be >= anomaly.ml_score.score_threshold -- otherwise an identity gets blocked with no corresponding ml_score anomaly ever logged")
			}
			if c.Anomaly.AutoBlock.BlockDurationSeconds <= 0 {
				problems = append(problems, "anomaly.auto_block.block_duration_seconds must be > 0 when anomaly.auto_block.enabled is true")
			}
			if c.Anomaly.AutoBlock.BlockDurationSeconds > 2*c.Anomaly.GCIntervalSeconds {
				problems = append(problems, fmt.Sprintf(
					"anomaly.auto_block.block_duration_seconds (%d) must be <= 2x anomaly.gc_interval_seconds (%d, so <= %d) -- otherwise a blocked identity's baseline can be garbage-collected mid-block, silently resetting it instead of freezing it",
					c.Anomaly.AutoBlock.BlockDurationSeconds, c.Anomaly.GCIntervalSeconds, 2*c.Anomaly.GCIntervalSeconds))
			}
		}
	}
	if c.Features["federation"] {
		if !c.Features["anomaly_detection"] {
			problems = append(problems, "features.anomaly_detection must be true when features.federation is true -- federation shares this instance's own local anomaly detections")
		}
		if c.Federation.PeersFile == "" {
			problems = append(problems, "federation.peers_file must not be empty when features.federation is true")
		}
		if c.Federation.SigningKeyFile == "" {
			problems = append(problems, "federation.signing_key_file must not be empty when features.federation is true")
		}
		if c.Federation.SharedSecretFile == "" {
			problems = append(problems, "federation.shared_secret_file must not be empty when features.federation is true")
		}
		if c.Federation.PublishIntervalSeconds <= 0 {
			problems = append(problems, "federation.publish_interval_seconds must be > 0 when features.federation is true")
		}
		if c.Federation.MinInstancesForCorrelation < 2 {
			problems = append(problems, "federation.min_instances_for_correlation must be >= 2 when features.federation is true")
		}
		if c.Federation.CorrelationWindowSeconds <= 0 {
			problems = append(problems, "federation.correlation_window_seconds must be > 0 when features.federation is true")
		}
		if c.Federation.GCIntervalSeconds <= 0 {
			problems = append(problems, "federation.gc_interval_seconds must be > 0 when features.federation is true")
		}
	}
	if c.ShutdownDelaySeconds < 0 {
		problems = append(problems, fmt.Sprintf("shutdown_delay_seconds must be >= 0, got %d", c.ShutdownDelaySeconds))
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
