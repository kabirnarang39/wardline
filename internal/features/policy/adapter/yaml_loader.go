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
	Tenant   string `yaml:"tenant"`
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
	m, err := ParseYAML(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// ParseYAML validates and parses policy YAML content already in memory,
// the half of LoadFile's work that doesn't need a filesystem path --
// extracted so a caller writing NEW policy content (the dashboard's
// structured rule editor, see WriteFile) can validate it BEFORE
// persisting anything, rather than writing first and finding out via a
// separate reload attempt. Returns an error describing every problem
// found (not just the first), matching LoadFile's own contract exactly.
func ParseYAML(data []byte) (*usecase.Matcher, error) {
	rules, def, err := ParseRules(data)
	if err != nil {
		return nil, err
	}
	return usecase.NewMatcher(rules, def), nil
}

// ParseRules is ParseYAML's other half: the raw, validated rule slice
// and default effect, without wrapping them in an opaque Matcher --
// usecase.Matcher deliberately exposes no way to read its rules back
// out (Evaluate only), so a caller that needs the actual rule list
// (the dashboard's GET /dashboard/api/policy, populating the Rule
// editor's table from the real, currently-loaded rules rather than a
// hand-rolled duplicate YAML parser in JS) calls this directly. Same
// decode-and-validate logic as ParseYAML, same "every problem, not just
// the first" error contract.
func ParseRules(data []byte) ([]domain.Rule, domain.Effect, error) {
	var raw policyYAML
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, "", fmt.Errorf("parse policy: %w", err)
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
		rules = append(rules, domain.Rule{Identity: r.Identity, Tool: r.Tool, Effect: effect, Tenant: r.Tenant})
	}

	def, err := parseEffect(raw.Default)
	if err != nil {
		problems = append(problems, fmt.Sprintf("default: %v", err))
	}

	if len(problems) > 0 {
		return nil, "", fmt.Errorf("invalid policy:\n  - %s", strings.Join(problems, "\n  - "))
	}

	return rules, def, nil
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
