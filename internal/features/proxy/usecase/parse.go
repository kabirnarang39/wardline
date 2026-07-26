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

// ParseToolCall extracts a ToolCall from an MCP JSON-RPC "tools/call"
// request body. identity comes from the caller (e.g. a request header),
// not from the body. It also returns the request's JSON-RPC id (or a JSON
// "null" if the id couldn't be determined) so callers can echo it back in
// a JSON-RPC error response.
func ParseToolCall(identity string, body []byte) (domain.ToolCall, json.RawMessage, error) {
	var env jsonRPCEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return domain.ToolCall{}, nullID, fmt.Errorf("parse json-rpc body: %w", err)
	}
	id := env.ID
	if len(id) == 0 {
		id = nullID
	}
	if env.Method != "tools/call" {
		return domain.ToolCall{}, id, fmt.Errorf("unsupported method %q", env.Method)
	}
	var params toolCallParams
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &params); err != nil {
			return domain.ToolCall{}, id, fmt.Errorf("parse params: %w", err)
		}
	}
	if params.Name == "" {
		return domain.ToolCall{}, id, fmt.Errorf("missing tool name")
	}
	return domain.ToolCall{Identity: identity, Tool: params.Name, Params: env.Params}, id, nil
}
