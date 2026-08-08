package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

func TestParseRequest_ToolsCall_Valid(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)
	parsed, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.IsToolCall {
		t.Fatal("expected IsToolCall=true for a tools/call method")
	}
	if !parsed.IsGated {
		t.Fatal("expected IsGated=true for a tools/call method")
	}
	if parsed.Call.Identity != "agent-abc123" || parsed.Call.Tool != "read_file" || parsed.Call.Tenant != "acme" || parsed.Call.Method != "tools/call" {
		t.Errorf("unexpected call: %+v", parsed.Call)
	}
	if parsed.Method != "tools/call" {
		t.Errorf("expected Method %q, got %q", "tools/call", parsed.Method)
	}
	if string(parsed.ID) != "1" {
		t.Errorf("expected id 1, got %s", parsed.ID)
	}
}

func TestParseRequest_MalformedJSON(t *testing.T) {
	parsed, err := usecase.ParseRequest("agent-abc123", "acme", []byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if string(parsed.ID) != "null" {
		t.Errorf("expected id to default to null when the id can't even be extracted, got %s", parsed.ID)
	}
}

func TestParseRequest_MissingMethodField(t *testing.T) {
	// A well-formed JSON object with no "method" key at all is not a
	// valid JSON-RPC request (method is mandatory per the spec) — must
	// still be a parse error, not silently treated as a passthrough with
	// an empty method name.
	body := []byte(`{"jsonrpc":"2.0","id":1,"params":{}}`)
	_, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err == nil {
		t.Fatal("expected error for a JSON-RPC envelope missing \"method\"")
	}
}

func TestParseRequest_NonToolCallMethodPassesThrough(t *testing.T) {
	// Deliberately excludes resources/*/prompts/* methods -- those are
	// gated now (see TestParseRequest_ResourcesAndPromptsMethodsAreGated
	// below), this test guards the true protocol-lifecycle/discovery set
	// that must stay ungated.
	for _, method := range []string{"initialize", "notifications/initialized", "tools/list", "ping"} {
		t.Run(method, func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`)
			parsed, err := usecase.ParseRequest("agent-abc123", "acme", body)
			if err != nil {
				t.Fatalf("unexpected error for method %q: %v", method, err)
			}
			if parsed.IsToolCall {
				t.Errorf("expected IsToolCall=false for method %q", method)
			}
			if parsed.IsGated {
				t.Errorf("expected IsGated=false for method %q", method)
			}
			if parsed.Method != method {
				t.Errorf("expected Method %q, got %q", method, parsed.Method)
			}
		})
	}
}

// TestParseRequest_ResourcesAndPromptsMethodsAreGated is the widening
// feature's core proof: resources/* and prompts/* methods are now
// policy-evaluated (IsGated=true), but never budget-checked
// (IsToolCall=false) -- see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
func TestParseRequest_ResourcesAndPromptsMethodsAreGated(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		params     string
		wantTarget string
	}{
		{"resources/read with uri", "resources/read", `{"uri":"file:///data/report.csv"}`, "file:///data/report.csv"},
		{"resources/list untargeted", "resources/list", `{}`, ""},
		{"resources/list no params at all", "resources/list", ``, ""},
		{"prompts/get with name", "prompts/get", `{"name":"summarize","arguments":{"x":1}}`, "summarize"},
		{"prompts/list untargeted", "prompts/list", `{}`, ""},
		{"resources/subscribe (prefix match, not enumerated)", "resources/subscribe", `{"uri":"file:///x"}`, "file:///x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + tc.method + `","params":` + func() string {
				if tc.params == "" {
					return "null"
				}
				return tc.params
			}() + `}`)
			parsed, err := usecase.ParseRequest("agent-abc123", "acme", body)
			if err != nil {
				t.Fatalf("unexpected error for method %q: %v", tc.method, err)
			}
			if !parsed.IsGated {
				t.Errorf("expected IsGated=true for method %q", tc.method)
			}
			if parsed.IsToolCall {
				t.Errorf("expected IsToolCall=false for method %q (budget must not widen)", tc.method)
			}
			if parsed.Call.Tool != tc.wantTarget {
				t.Errorf("method %q: got target %q, want %q", tc.method, parsed.Call.Tool, tc.wantTarget)
			}
			if parsed.Call.Method != tc.method {
				t.Errorf("method %q: Call.Method = %q, want %q", tc.method, parsed.Call.Method, tc.method)
			}
			if parsed.Call.Identity != "agent-abc123" || parsed.Call.Tenant != "acme" {
				t.Errorf("method %q: unexpected identity/tenant: %+v", tc.method, parsed.Call)
			}
		})
	}
}

// TestParseRequest_ResourcesReadMalformedParamsIsParseError proves a
// gated resources/prompts method still hard-errors on genuinely
// unparsable params, same as tools/call does today -- widening what's
// evaluated must not widen what counts as malformed.
func TestParseRequest_ResourcesReadMalformedParamsIsParseError(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":"oops"}`)
	_, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err == nil {
		t.Fatal("expected error for non-object params on a gated resources/prompts method")
	}
}

func TestParseRequest_NotificationWithNoID(t *testing.T) {
	// JSON-RPC notifications legally omit "id" entirely — must not be
	// treated as an error just because ID is absent.
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	parsed, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.IsToolCall {
		t.Error("expected IsToolCall=false")
	}
	if string(parsed.ID) != "null" {
		t.Errorf("expected id to default to null, got %s", parsed.ID)
	}
}

func TestParseRequest_ToolsCall_EmptyParams(t *testing.T) {
	body := []byte(`{"method":"tools/call","params":{}}`)
	_, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err == nil {
		t.Fatal("expected error for empty params (no tool name)")
	}
}

func TestParseRequest_ToolsCall_MissingParams(t *testing.T) {
	body := []byte(`{"method":"tools/call"}`)
	_, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err == nil {
		t.Fatal("expected error for missing params field")
	}
}

func TestParseRequest_ToolsCall_EmptyToolName(t *testing.T) {
	body := []byte(`{"method":"tools/call","params":{"name":""}}`)
	_, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err == nil {
		t.Fatal("expected error for empty tool name")
	}
}

func TestParseRequest_ToolsCall_NonObjectParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":"oops"}`)
	parsed, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err == nil {
		t.Fatal("expected error for non-object params")
	}
	if string(parsed.ID) != "7" {
		t.Errorf("expected the request's real id 7 (envelope parsed fine), got %s", parsed.ID)
	}
}

func TestParseRequest_ToolsCall_PreservesRawParams(t *testing.T) {
	// Deliberately non-canonical spacing and an unrecognized key: proves
	// ToolCall.Params carries the exact params bytes through unchanged.
	rawParams := `{"name":"read_file", "path":"/tmp/x","extra_field":123}`
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + rawParams + `}`)
	parsed, err := usecase.ParseRequest("agent-abc123", "acme", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(parsed.Call.Params) != rawParams {
		t.Errorf("expected Params to equal the exact raw bytes sent:\n got:  %s\n want: %s", parsed.Call.Params, rawParams)
	}
}
