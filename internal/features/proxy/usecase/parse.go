package usecase

import (
	"encoding/json"
	"fmt"

	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

type jsonRPCEnvelope struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// ParseToolCall extracts a ToolCall from an MCP JSON-RPC "tools/call"
// request body. identity comes from the caller (e.g. a request header),
// not from the body.
func ParseToolCall(identity string, body []byte) (domain.ToolCall, error) {
	var env jsonRPCEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return domain.ToolCall{}, fmt.Errorf("parse json-rpc body: %w", err)
	}
	if env.Method != "tools/call" {
		return domain.ToolCall{}, fmt.Errorf("unsupported method %q", env.Method)
	}
	return domain.ToolCall{Identity: identity, Tool: env.Params.Name}, nil
}
