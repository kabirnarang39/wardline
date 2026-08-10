package domain

import (
	"encoding/json"
	"time"
)

// Effect is the outcome of a policy rule: allow, needs_approval, or deny.
type Effect string

const (
	EffectAllow         Effect = "allow"
	EffectDeny          Effect = "deny"
	EffectNeedsApproval Effect = "needs_approval"
)

// Rule grants or denies a specific identity access to a specific tool (or,
// since the resources/prompts widening, a specific resource URI or prompt
// name — see Method). Tool may be "*" to match any target for that
// identity+method.
//
// Tenant scopes the rule to a single tenant; "" means the rule is global
// and matches any tenant, the same "empty means global" convention used by
// RBAC's RoleBinding/ClusterRoleBinding.
type Rule struct {
	Identity string
	Tool     string
	Effect   Effect
	Tenant   string

	// Method is the JSON-RPC method this rule applies to: "tools/call",
	// or an MCP resources/*/prompts/* method (e.g. "resources/read",
	// "prompts/get", "resources/list"). "" means "tools/call" — every
	// rule written before this field existed keeps matching exactly what
	// it matched before, with zero required edits to an existing
	// policy.yaml.
	Method string
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
	Identity string

	// Tool is the authoritative tool name, as extracted by Wardline's own
	// JSON parser. A policy should always key decisions off Tool, never
	// re-parse Params looking for a "name" key — a body with duplicate
	// JSON keys could be interpreted differently by a different JSON
	// parser than the one Wardline used, a confused-deputy risk in a
	// security-relevant proxy.
	Tool string

	// Params is the whole MCP "params" object as sent by the client, not
	// just the tool's arguments — a real "tools/call" params typically
	// looks like {"name":"...", "arguments":{...}}, so a policy wanting
	// tool arguments should read params.arguments.*, not assume the top
	// level IS the arguments.
	//
	// On a successful ParseRequest, Params is always a non-nil JSON
	// object containing a non-empty "name" key: non-object params are
	// rejected, and a null/omitted params falls through to the
	// empty-name rejection, so a policy engine only ever sees a call
	// that reached policy evaluation. Params is nil only when a Context
	// is constructed by hand (e.g. in tests) rather than via the real
	// parse path.
	Params json.RawMessage

	Timestamp time.Time

	// RemoteAddr is http.Request.RemoteAddr — the direct TCP peer's
	// host:port as seen by Wardline itself, NOT resolved through
	// X-Forwarded-For or similar proxy headers. Behind a load balancer
	// or ingress, this is the LB's address on every request, not the
	// original client's; a future policy keying off network origin needs
	// XFF-awareness added explicitly (not yet implemented — a known
	// limitation, not a bug in this field's current behavior).
	RemoteAddr string
	UserAgent  string

	// Tenant is the calling identity's tenant. "" means no tenant scoping
	// applies to this call (matches only untenanted, global Rules).
	Tenant string

	// Method is the JSON-RPC method this call arrived as: "tools/call",
	// or a gated resources/*/prompts/* method (e.g. "resources/read").
	// A rule with Method == "" is treated as "tools/call" when matching
	// against this field — see Rule.Method.
	Method string

	// Tainted reports whether the calling identity's session currently
	// carries an integrity taint (it read from an untrusted source within
	// the taint TTL). Populated only when the taint_tracking feature is on;
	// always false otherwise, so a policy referencing input.tainted behaves
	// identically to before when the feature is off. Engine-neutral: exposed
	// to Rego as input.tainted today, readable by other engines later.
	Tainted bool
}

// Engine evaluates whether a Context's identity may make its tool call.
type Engine interface {
	Evaluate(pc Context) Decision
}
