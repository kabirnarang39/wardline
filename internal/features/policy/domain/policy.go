package domain

import (
	"encoding/json"
	"time"
)

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

// Decision is the result of evaluating a Context against policy.
type Decision struct {
	Effect Effect
	Reason string
}

// Context is everything a policy engine may consider when evaluating a
// tool call: who's calling, what they're calling, with what arguments,
// when, and from where. A YAML-rule-matching Engine only reads Identity
// and Tool; an OPA-backed Engine may read any of these fields.
type Context struct {
	Identity   string
	Tool       string
	Params     json.RawMessage
	Timestamp  time.Time
	RemoteAddr string
	UserAgent  string
}

// Engine evaluates whether a Context's identity may make its tool call.
type Engine interface {
	Evaluate(ctx Context) Decision
}
