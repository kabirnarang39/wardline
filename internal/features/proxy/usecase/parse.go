package usecase

import (
	"encoding/json"
	"fmt"

	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

// nullID is the JSON-RPC id to echo back when the real id can't be
// determined (body unreadable/unparsable, or the request omitted "id").
var nullID = json.RawMessage("null")

type jsonRPCEnvelope struct {
	// ID can legally be a string, number, or null in JSON-RPC 2.0; capture
	// it as-is so error responses can echo it back without interpreting it.
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// toolCallParams extracts just the tool name from an envelope's raw
// params; the full raw bytes are preserved separately on ToolCall.Params
// for policy engines that need more than the name.
type toolCallParams struct {
	Name string `json:"name"`
}

// ParseRequest parses an incoming MCP JSON-RPC request body. identity
// comes from the caller (e.g. a request header), not from the body.
//
// A "tools/call" method returns IsToolCall=true with Call populated —
// the existing policy/budget-evaluated path. Any other well-formed
// JSON-RPC method (initialize, notifications/initialized, tools/list,
// etc.) returns IsToolCall=false with Method populated and Call at its
// zero value — Wardline's policy model is scoped to tool calls, so
// these are the caller's signal to forward the request to upstream
// without policy or budget evaluation, per
// docs/superpowers/specs/2026-07-27-mcp-protocol-passthrough-design.md.
//
// An error is returned only for a genuinely malformed request: unparsable
// JSON, a JSON-RPC envelope missing the mandatory "method" field, or (for
// "tools/call" specifically) missing/malformed tool-call params.
func ParseRequest(identity string, body []byte) (domain.ParsedRequest, error) {
	var env jsonRPCEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return domain.ParsedRequest{}, fmt.Errorf("parse json-rpc body: %w", err)
	}
	id := env.ID
	if len(id) == 0 {
		id = nullID
	}
	if env.Method == "" {
		return domain.ParsedRequest{ID: id}, fmt.Errorf("missing required json-rpc \"method\" field")
	}

	if env.Method != "tools/call" {
		return domain.ParsedRequest{Method: env.Method, ID: id, IsToolCall: false}, nil
	}

	var params toolCallParams
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &params); err != nil {
			return domain.ParsedRequest{ID: id}, fmt.Errorf("parse params: %w", err)
		}
	}
	if params.Name == "" {
		return domain.ParsedRequest{ID: id}, fmt.Errorf("missing tool name")
	}
	return domain.ParsedRequest{
		Call:       domain.ToolCall{Identity: identity, Tool: params.Name, Params: env.Params},
		Method:     env.Method,
		ID:         id,
		IsToolCall: true,
	}, nil
}
