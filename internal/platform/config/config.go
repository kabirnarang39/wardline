package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type AuditConfig struct {
	Output string `yaml:"output"` // "stdout" or a file path
}

// Config is Wardline's top-level operator configuration. Features holds
// flag toggles for capabilities added after v0.1 (none exist yet — this
// field exists so internal/platform/flags has something to read from
// without a later breaking config change).
type Config struct {
	Listen     string          `yaml:"listen"`
	Upstream   string          `yaml:"upstream"`
	PolicyFile string          `yaml:"policy_file"`
	Audit      AuditConfig     `yaml:"audit"`
	Features   map[string]bool `yaml:"features"`

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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
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
	if c.Audit.Output == "" {
		problems = append(problems, "audit.output must not be empty")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
