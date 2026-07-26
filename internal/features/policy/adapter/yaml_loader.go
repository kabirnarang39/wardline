package adapter

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/policy/usecase"
)

type ruleYAML struct {
	Identity string `yaml:"identity"`
	Tool     string `yaml:"tool"`
	Effect   string `yaml:"effect"`
}

type policyYAML struct {
	Rules   []ruleYAML `yaml:"rules"`
	Default string     `yaml:"default"`
}

// LoadFile reads a policy YAML file and returns a usecase.Matcher, or an
// error describing every problem found (not just the first).
func LoadFile(path string) (*usecase.Matcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}

	var raw policyYAML
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse policy file %s: %w", path, err)
	}

	var problems []string
	rules := make([]domain.Rule, 0, len(raw.Rules))
	for i, r := range raw.Rules {
		effect, err := parseEffect(r.Effect)
		if err != nil {
			problems = append(problems, fmt.Sprintf("rule %d: %v", i, err))
			continue
		}
		if r.Identity == "" {
			problems = append(problems, fmt.Sprintf("rule %d: identity must not be empty", i))
		}
		if r.Tool == "" {
			problems = append(problems, fmt.Sprintf("rule %d: tool must not be empty", i))
		}
		rules = append(rules, domain.Rule{Identity: r.Identity, Tool: r.Tool, Effect: effect})
	}

	def, err := parseEffect(raw.Default)
	if err != nil {
		problems = append(problems, fmt.Sprintf("default: %v", err))
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid policy file %s:\n  - %s", path, strings.Join(problems, "\n  - "))
	}

	return usecase.NewMatcher(rules, def), nil
}

func parseEffect(s string) (domain.Effect, error) {
	switch domain.Effect(s) {
	case domain.EffectAllow:
		return domain.EffectAllow, nil
	case domain.EffectDeny:
		return domain.EffectDeny, nil
	default:
		return "", fmt.Errorf("effect must be %q or %q, got %q", domain.EffectAllow, domain.EffectDeny, s)
	}
}
