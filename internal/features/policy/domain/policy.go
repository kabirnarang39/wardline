package domain

// Effect is the outcome of a policy rule: allow or deny.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule grants or denies a specific identity access to a specific tool.
// Tool may be "*" to match any tool for that identity.
type Rule struct {
	Identity string
	Tool     string
	Effect   Effect
}

// Decision is the result of evaluating an identity+tool pair against policy.
type Decision struct {
	Effect Effect
	Reason string
}

// Engine evaluates whether an identity may call a tool.
type Engine interface {
	Evaluate(identity, tool string) Decision
}
