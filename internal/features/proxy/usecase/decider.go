package usecase

import (
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

// Decider evaluates a ToolCall against the policy engine and returns
// whether the call may proceed. The engine is held behind a
// ReloadableEngine so a hot reload takes effect on the very next Decide
// call, on this same Decider instance, with no restart.
type Decider struct {
	policy *reload.ReloadableEngine[policydomain.Engine]
}

// NewDecider wraps policy in a fresh, private ReloadableEngine holder --
// callers that don't care about reload (most existing tests and
// call sites) keep working unchanged. Use NewDeciderWithHolder when the
// caller needs to reload the engine later via the same holder.
func NewDecider(policy policydomain.Engine) *Decider {
	return &Decider{policy: reload.NewReloadableEngine(&policy)}
}

// NewDeciderWithHolder builds a Decider backed by an existing
// ReloadableEngine holder, so a later Swap on that holder (e.g. from the
// policy hot-reload path in main.go) is observed by this Decider on its
// very next Decide call.
func NewDeciderWithHolder(holder *reload.ReloadableEngine[policydomain.Engine]) *Decider {
	return &Decider{policy: holder}
}

func (d *Decider) Decide(call domain.ToolCall) domain.Verdict {
	pc := policydomain.Context{
		Identity:   call.Identity,
		Tenant:     call.Tenant,
		Tool:       call.Tool,
		Method:     call.Method,
		Params:     call.Params,
		Timestamp:  call.Timestamp,
		RemoteAddr: call.RemoteAddr,
		UserAgent:  call.UserAgent,
	}
	engine := *d.policy.Current()
	decision := engine.Evaluate(pc)
	return domain.Verdict{
		Allow:  decision.Effect == policydomain.EffectAllow,
		Reason: decision.Reason,
	}
}
