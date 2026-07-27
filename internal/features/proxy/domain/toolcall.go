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

	// Tool is the authoritative tool name, extracted by Wardline's own
	// JSON parser. Downstream consumers (policy, audit) should always
	// key off Tool, never re-parse Params looking for a "name" key.
	Tool string

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
// request body. IsToolCall distinguishes a "tools/call" request (Call
// is populated, goes through policy/budget evaluation) from any other
// well-formed JSON-RPC method (Method is populated, Call is the zero
// value — these are protocol-lifecycle/discovery methods like
// "initialize" or "tools/list" that every real MCP client sends before
// its first tool call, and Wardline's policy model is scoped to tool
// calls only, so these are forwarded to upstream without evaluation).
type ParsedRequest struct {
	Call       ToolCall
	Method     string
	ID         json.RawMessage
	IsToolCall bool
}
