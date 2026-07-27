package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

func TestParseRequest_ToolsCall_Valid(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)
	parsed, err := usecase.ParseRequest("agent-abc123", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.IsToolCall {
		t.Fatal("expected IsToolCall=true for a tools/call method")
	}
	if parsed.Call.Identity != "agent-abc123" || parsed.Call.Tool != "read_file" {
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
	parsed, err := usecase.ParseRequest("agent-abc123", []byte(`not json`))
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
	_, err := usecase.ParseRequest("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for a JSON-RPC envelope missing \"method\"")
	}
}

func TestParseRequest_NonToolCallMethodPassesThrough(t *testing.T) {
	for _, method := range []string{"initialize", "notifications/initialized", "tools/list", "resources/list", "ping"} {
		t.Run(method, func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`)
			parsed, err := usecase.ParseRequest("agent-abc123", body)
			if err != nil {
				t.Fatalf("unexpected error for method %q: %v", method, err)
			}
			if parsed.IsToolCall {
				t.Errorf("expected IsToolCall=false for method %q", method)
			}
			if parsed.Method != method {
				t.Errorf("expected Method %q, got %q", method, parsed.Method)
			}
		})
	}
}

func TestParseRequest_NotificationWithNoID(t *testing.T) {
	// JSON-RPC notifications legally omit "id" entirely — must not be
	// treated as an error just because ID is absent.
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	parsed, err := usecase.ParseRequest("agent-abc123", body)
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
	_, err := usecase.ParseRequest("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for empty params (no tool name)")
	}
}

func TestParseRequest_ToolsCall_MissingParams(t *testing.T) {
	body := []byte(`{"method":"tools/call"}`)
	_, err := usecase.ParseRequest("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for missing params field")
	}
}

func TestParseRequest_ToolsCall_EmptyToolName(t *testing.T) {
	body := []byte(`{"method":"tools/call","params":{"name":""}}`)
	_, err := usecase.ParseRequest("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for empty tool name")
	}
}

func TestParseRequest_ToolsCall_NonObjectParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":"oops"}`)
	parsed, err := usecase.ParseRequest("agent-abc123", body)
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
	parsed, err := usecase.ParseRequest("agent-abc123", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(parsed.Call.Params) != rawParams {
		t.Errorf("expected Params to equal the exact raw bytes sent:\n got:  %s\n want: %s", parsed.Call.Params, rawParams)
	}
}
