package domain

// ToolCall is the parsed intent of an incoming MCP JSON-RPC request: which
// identity is trying to call which tool.
type ToolCall struct {
	Identity string
	Tool     string
}

// Verdict is the result of evaluating a ToolCall against policy.
type Verdict struct {
	Allow  bool
	Reason string
}
