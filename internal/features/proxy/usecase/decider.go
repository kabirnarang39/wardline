package usecase

import (
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

// Decider evaluates a ToolCall against the policy engine and returns
// whether the call may proceed.
type Decider struct {
	policy policydomain.Engine
}

func NewDecider(policy policydomain.Engine) *Decider {
	return &Decider{policy: policy}
}

func (d *Decider) Decide(call domain.ToolCall) domain.Verdict {
	decision := d.policy.Evaluate(call.Identity, call.Tool)
	return domain.Verdict{
		Allow:  decision.Effect == policydomain.EffectAllow,
		Reason: decision.Reason,
	}
}
