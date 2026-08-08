package domain

import (
	"encoding/json"
	"time"
)

// ToolCall is the parsed intent of an incoming MCP JSON-RPC request: which
// identity is trying to call which tool, with what arguments, when, and
// from where.
type ToolCall struct {
	Identity string

	// Tenant is the calling identity's tenant, resolved by
	// IdentityAuthenticator alongside Identity. "" means no tenant
	// scoping applies (see policydomain.Context.Tenant).
	Tenant string

	// Tool is the authoritative target identifier, extracted by Wardline's
	// own JSON parser: the tool name for a "tools/call", or (since the
	// resources/prompts widening) a resource URI for "resources/read" or
	// a prompt name for "prompts/get". "" for an untargeted
	// resources/prompts method (e.g. "resources/list") — see Method.
	// Downstream consumers (policy, audit) should always key off Tool,
	// never re-parse Params looking for a "name"/"uri" key.
	Tool string

	// Method is the JSON-RPC method this call arrived as ("tools/call",
	// "resources/read", "prompts/get", etc.), always populated for a
	// gated request (see domain.ParsedRequest.IsGated).
	Method string

	Params     json.RawMessage
	Timestamp  time.Time
	RemoteAddr string
	UserAgent  string
}

// Verdict is the result of evaluating a ToolCall against policy.
type Verdict struct {
	Allow  bool
	Reason string
}

// ParsedRequest is the result of parsing an incoming MCP JSON-RPC
// request body. IsGated distinguishes a policy-evaluated request (Call
// is populated) from a true protocol-lifecycle/discovery method like
// "initialize" or "tools/list" (Method is populated, Call is the zero
// value) that's forwarded to upstream without any evaluation. IsToolCall
// is the narrower "exactly tools/call" signal: every gated request runs
// through policy, but only a tools/call additionally runs through the
// budget checker — see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md
// for why budget enforcement doesn't widen along with policy.
type ParsedRequest struct {
	Call       ToolCall
	Method     string
	ID         json.RawMessage
	IsToolCall bool
	IsGated    bool
}
