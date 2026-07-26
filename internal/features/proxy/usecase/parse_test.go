package usecase_test

import (
	"encoding/json"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

func TestParseToolCall_Valid(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)
	call, id, err := usecase.ParseToolCall("agent-abc123", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.Identity != "agent-abc123" || call.Tool != "read_file" {
		t.Errorf("unexpected call: %+v", call)
	}
	if string(id) != "1" {
		t.Errorf("expected id 1, got %s", id)
	}
}

func TestParseToolCall_MalformedJSON(t *testing.T) {
	_, id, err := usecase.ParseToolCall("agent-abc123", []byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if string(id) != "null" {
		t.Errorf("expected null id for unparsable body, got %s", id)
	}
}

func TestParseToolCall_UnsupportedMethod(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{}}`)
	_, _, err := usecase.ParseToolCall("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

func TestParseToolCall_EmptyParams(t *testing.T) {
	body := []byte(`{"method":"tools/call","params":{}}`)
	_, _, err := usecase.ParseToolCall("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for empty params (no tool name)")
	}
}

func TestParseToolCall_MissingParams(t *testing.T) {
	body := []byte(`{"method":"tools/call"}`)
	_, _, err := usecase.ParseToolCall("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for missing params field")
	}
}

func TestParseToolCall_EmptyToolName(t *testing.T) {
	body := []byte(`{"method":"tools/call","params":{"name":""}}`)
	_, _, err := usecase.ParseToolCall("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for empty tool name")
	}
}

func TestParseToolCall_NonObjectParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":"oops"}`)
	_, id, err := usecase.ParseToolCall("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for non-object params")
	}
	if string(id) != "7" {
		t.Errorf("expected the request's real id 7 (envelope parsed fine), got %s", id)
	}
}

func TestParseToolCall_PreservesRawParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","path":"/tmp/x"}}`)
	call, _, err := usecase.ParseToolCall("agent-abc123", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(call.Params, &got); err != nil {
		t.Fatalf("ToolCall.Params did not unmarshal: %v", err)
	}
	if got.Name != "read_file" || got.Path != "/tmp/x" {
		t.Errorf("unexpected round-tripped params: %+v", got)
	}
}
