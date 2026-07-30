package usecase

import "github.com/kabirnarang39/wardline/internal/features/policy/domain"

// Matcher is a domain.Engine backed by an ordered list of rules,
// first-match-wins, falling back to Default when nothing matches. It only
// reads Context.Identity, Context.Tool, and Context.Tenant — every other
// field exists for engines that need richer input than static YAML rules
// can express.
type Matcher struct {
	Rules   []domain.Rule
	Default domain.Effect
}

func NewMatcher(rules []domain.Rule, def domain.Effect) *Matcher {
	return &Matcher{Rules: rules, Default: def}
}

func (m *Matcher) Evaluate(pc domain.Context) domain.Decision {
	for _, r := range m.Rules {
		if r.Identity != pc.Identity {
			continue
		}
		if (r.Tool == pc.Tool || r.Tool == "*") && (r.Tenant == "" || r.Tenant == pc.Tenant) {
			return domain.Decision{Effect: r.Effect, Reason: "matched rule"}
		}
	}
	return domain.Decision{Effect: m.Default, Reason: "default"}
}
