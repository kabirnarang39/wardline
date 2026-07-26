package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

func TestParseToolCall_Valid(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`)
	call, err := usecase.ParseToolCall("agent-abc123", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.Identity != "agent-abc123" || call.Tool != "read_file" {
		t.Errorf("unexpected call: %+v", call)
	}
}

func TestParseToolCall_MalformedJSON(t *testing.T) {
	_, err := usecase.ParseToolCall("agent-abc123", []byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseToolCall_UnsupportedMethod(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{}}`)
	_, err := usecase.ParseToolCall("agent-abc123", body)
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
}
