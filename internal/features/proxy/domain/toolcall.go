package domain

import (
	"encoding/json"
	"time"
)

// ToolCall is the parsed intent of an incoming MCP JSON-RPC request: which
// identity is trying to call which tool, with what arguments, when, and
// from where.
type ToolCall struct {
	Identity   string
	Tool       string
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
