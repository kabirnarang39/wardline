package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuditConfig configures where audit entries are recorded. Output is
// used unless postgres_storage is on, in which case PostgresDSN is used
// instead — see Config.validate() and postgres_storage's flag gating.
type AuditConfig struct {
	Output      string `yaml:"output"`       // "stdout" or a file path
	PostgresDSN string `yaml:"postgres_dsn"` // only used when features.postgres_storage is true
}

// BudgetConfig configures the per-identity rate limiter. Only validated
// (and only meaningful) when the budget_enforcement feature flag is on.
type BudgetConfig struct {
	RequestsPerWindow int `yaml:"requests_per_window"`
	WindowSeconds     int `yaml:"window_seconds"`
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

// TracingConfig configures OTLP/HTTP span export. Only validated (and
// only meaningful) when the otel_tracing feature flag is on.
type TracingConfig struct {
	OTLPEndpoint string `yaml:"otlp_endpoint"` // host:port, no scheme
	ServiceName  string `yaml:"service_name"`  // defaults to "wardline"
}

// Config is Wardline's top-level operator configuration. Features holds
// flag toggles for capabilities added after v0.1 — budget_enforcement and
// otel_tracing are the two real ones so far; internal/platform/flags
// reads this map to decide whether a flagged feature is on.
type Config struct {
	Listen         string          `yaml:"listen"`
	Upstream       string          `yaml:"upstream"`
	PolicyFile     string          `yaml:"policy_file"`
	PolicyBackend  string          `yaml:"policy_backend"` // "yaml" (default) or "opa"
	Audit          AuditConfig     `yaml:"audit"`
	Budget         BudgetConfig    `yaml:"budget"`
	Tracing        TracingConfig   `yaml:"tracing"`
	Features       map[string]bool `yaml:"features"`

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
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
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
	} else if c.PolicyBackend != "yaml" && c.PolicyBackend != "opa" {
		problems = append(problems, fmt.Sprintf(`policy_backend must be "yaml" or "opa", got %q`, c.PolicyBackend))
	}
	if c.Features["postgres_storage"] {
		if c.Audit.PostgresDSN == "" {
			problems = append(problems, "audit.postgres_dsn must not be empty when features.postgres_storage is true")
		}
	} else if c.Audit.Output == "" {
		problems = append(problems, "audit.output must not be empty (or set features.postgres_storage: true and audit.postgres_dsn instead)")
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
	}
	if c.Features["otel_tracing"] {
		if c.Tracing.OTLPEndpoint == "" {
			problems = append(problems, "tracing.otlp_endpoint must not be empty when features.otel_tracing is true")
		}
		if c.Tracing.ServiceName == "" {
			c.Tracing.ServiceName = defaultTracingServiceName
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
