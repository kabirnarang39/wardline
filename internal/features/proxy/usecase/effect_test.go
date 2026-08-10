package usecase_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

func writeReq(tool string, params string) domain.ParsedRequest {
	return domain.ParsedRequest{
		Call:       domain.ToolCall{Tool: tool, Method: "tools/call", Params: json.RawMessage(params)},
		Method:     "tools/call",
		IsToolCall: true,
		IsGated:    true,
	}
}

func readReq(method, target string) domain.ParsedRequest {
	return domain.ParsedRequest{
		Call:       domain.ToolCall{Tool: target, Method: method},
		Method:     method,
		IsToolCall: false,
		IsGated:    true,
	}
}

func TestExtractEffect_OpaqueSuccessIsUnconfirmed(t *testing.T) {
	eff, st := usecase.ExtractEffect(writeReq("delete_file", `{"name":"delete_file","path":"/a"}`), usecase.EffectSignal{ResponseStatus: 200}, nil)
	assert.Equal(t, auditdomain.EffectStatusUnconfirmed, st)
	if assert.NotNil(t, eff) {
		assert.Equal(t, "delete_file", eff.Target)
		assert.Equal(t, "tools/call", eff.ClaimedOp)
		assert.Equal(t, "/a", eff.ClaimedArgs["path"])
	}
}

func TestExtractEffect_NoOpIsContradicted(t *testing.T) {
	_, st := usecase.ExtractEffect(writeReq("delete_file", `{}`), usecase.EffectSignal{ResponseStatus: 200, NoOpSignal: true}, nil)
	assert.Equal(t, auditdomain.EffectStatusContradicted, st)
}

func TestExtractEffect_RPCErrorIsContradicted(t *testing.T) {
	_, st := usecase.ExtractEffect(writeReq("delete_file", `{}`), usecase.EffectSignal{ResponseStatus: 200, RPCError: true}, nil)
	assert.Equal(t, auditdomain.EffectStatusContradicted, st)
}

func TestExtractEffect_HTTPErrorIsContradicted(t *testing.T) {
	_, st := usecase.ExtractEffect(writeReq("delete_file", `{}`), usecase.EffectSignal{ResponseStatus: 500}, nil)
	assert.Equal(t, auditdomain.EffectStatusContradicted, st)
}

func TestExtractEffect_ResourceReadIsNotAWrite(t *testing.T) {
	eff, st := usecase.ExtractEffect(readReq("resources/read", "file:///a"), usecase.EffectSignal{ResponseStatus: 200}, nil)
	assert.Nil(t, eff)
	assert.Equal(t, auditdomain.EffectStatusNotAWrite, st)
}

func TestExtractEffect_RedactionApplied(t *testing.T) {
	redact := func(m map[string]string) map[string]string {
		if _, ok := m["token"]; ok {
			m["token"] = "[REDACTED]"
		}
		return m
	}
	eff, _ := usecase.ExtractEffect(writeReq("set_secret", `{"token":"hunter2"}`), usecase.EffectSignal{ResponseStatus: 200}, redact)
	if assert.NotNil(t, eff) {
		assert.Equal(t, "[REDACTED]", eff.ClaimedArgs["token"])
	}
}
