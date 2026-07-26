package usecase

import "github.com/kabirnarang39/wardline/internal/features/policy/domain"

// Matcher is a domain.Engine backed by an ordered list of rules,
// first-match-wins, falling back to Default when nothing matches.
type Matcher struct {
	Rules   []domain.Rule
	Default domain.Effect
}

func NewMatcher(rules []domain.Rule, def domain.Effect) *Matcher {
	return &Matcher{Rules: rules, Default: def}
}

func (m *Matcher) Evaluate(identity, tool string) domain.Decision {
	for _, r := range m.Rules {
		if r.Identity != identity {
			continue
		}
		if r.Tool == tool || r.Tool == "*" {
			return domain.Decision{Effect: r.Effect, Reason: "matched rule"}
		}
	}
	return domain.Decision{Effect: m.Default, Reason: "default"}
}
