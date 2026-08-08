package usecase

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

// nullID is the JSON-RPC id to echo back when the real id can't be
// determined (body unreadable/unparsable, or the request omitted "id").
var nullID = json.RawMessage("null")

// methodToolsCall is the one MCP method that existed before the
// resources/prompts widening — kept as its own named constant since it's
// checked both for exact equality (isGatedMethod) and to pick the
// stricter "name is required" parsing branch below.
const methodToolsCall = "tools/call"

type jsonRPCEnvelope struct {
	// ID can legally be a string, number, or null in JSON-RPC 2.0; capture
	// it as-is so error responses can echo it back without interpreting it.
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// targetParams extracts an envelope's target identifier: a tool/prompt
// name ("tools/call", "prompts/get") or a resource URI ("resources/read").
// A spec-conformant client only ever populates one of these per method;
// Name wins if a body somehow sets both. The full raw bytes are preserved
// separately on ToolCall.Params for policy engines that need more than
// the target.
type targetParams struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

// isGatedMethod reports whether method is policy-evaluated: exactly
// "tools/call", or any "resources/*"/"prompts/*" method. A prefix match,
// not an enumerated method list, so a future MCP protocol revision adding
// new resources/prompts methods needs no change here — see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
func isGatedMethod(method string) bool {
	return method == methodToolsCall || strings.HasPrefix(method, "resources/") || strings.HasPrefix(method, "prompts/")
}

// ParseRequest parses an incoming MCP JSON-RPC request body. identity and
// tenantName come from the caller (already resolved by an
// IdentityAuthenticator, e.g. from a request header), not from the body.
//
// A gated method (isGatedMethod: "tools/call", or any
// "resources/*"/"prompts/*" method) returns IsGated=true with Call
// populated — the policy-evaluated path (only "tools/call" additionally
// sets IsToolCall=true, gating the budget check too — see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md).
// Any other well-formed JSON-RPC method (initialize,
// notifications/initialized, tools/list, etc.) returns IsGated=false with
// Method populated and Call at its zero value — these are protocol-
// lifecycle/discovery methods every real MCP client sends before its
// first tool call, forwarded to upstream without evaluation, per
// docs/superpowers/specs/2026-07-27-mcp-protocol-passthrough-design.md.
//
// An error is returned only for a genuinely malformed request: unparsable
// JSON, a JSON-RPC envelope missing the mandatory "method" field, a
// gated method with unparsable params, or (for "tools/call" specifically)
// a missing tool name.
func ParseRequest(identity, tenantName string, body []byte) (domain.ParsedRequest, error) {
	var env jsonRPCEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return domain.ParsedRequest{ID: nullID}, fmt.Errorf("parse json-rpc body: %w", err)
	}
	id := env.ID
	if len(id) == 0 {
		id = nullID
	}
	if env.Method == "" {
		return domain.ParsedRequest{ID: id}, fmt.Errorf("missing required json-rpc \"method\" field")
	}

	if !isGatedMethod(env.Method) {
		return domain.ParsedRequest{Method: env.Method, ID: id, IsToolCall: false, IsGated: false}, nil
	}

	var params targetParams
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &params); err != nil {
			return domain.ParsedRequest{ID: id}, fmt.Errorf("parse params: %w", err)
		}
	}

	if env.Method == methodToolsCall {
		if params.Name == "" {
			return domain.ParsedRequest{ID: id}, fmt.Errorf("missing tool name")
		}
		return domain.ParsedRequest{
			Call:       domain.ToolCall{Identity: identity, Tenant: tenantName, Tool: params.Name, Method: env.Method, Params: env.Params},
			Method:     env.Method,
			ID:         id,
			IsToolCall: true,
			IsGated:    true,
		}, nil
	}

	// resources/* or prompts/*: a target is optional (list-style methods
	// carry none) — "" is a valid Tool value here, unlike tools/call.
	target := params.Name
	if target == "" {
		target = params.URI
	}
	return domain.ParsedRequest{
		Call:       domain.ToolCall{Identity: identity, Tenant: tenantName, Tool: target, Method: env.Method, Params: env.Params},
		Method:     env.Method,
		ID:         id,
		IsToolCall: false,
		IsGated:    true,
	}, nil
}
