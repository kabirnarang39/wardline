package usecase

import (
	"encoding/json"
	"strings"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

// secretKeyHints are substrings that, when found in a param key (case-
// insensitive), mark its value as sensitive so RedactSecrets masks it. The
// audit trail is operator-only, but claimed-args can carry live credentials an
// agent passed to a tool, and the audit log is retained/exported — so mask by
// default and let nothing sensitive land in a bundle.
var secretKeyHints = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "auth", "credential", "private_key", "access_key"}

// RedactSecrets masks values whose key looks sensitive, returning a new map.
// Conservative and dependency-free — a real redaction pass, not a stub.
func RedactSecrets(args map[string]string) map[string]string {
	if len(args) == 0 {
		return args
	}
	out := make(map[string]string, len(args))
	for k, v := range args {
		lk := strings.ToLower(k)
		masked := false
		for _, hint := range secretKeyHints {
			if strings.Contains(lk, hint) {
				masked = true
				break
			}
		}
		if masked {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

// EffectSignal is the proxy-visible signal captured from the upstream
// response, fed into ExtractEffect. It is deliberately shallow: a proxy sees
// transport status and a bounded prefix of the body, not world-state.
type EffectSignal struct {
	ResponseStatus int
	RPCError       bool // JSON-RPC "error" present in the response body
	NoOpSignal     bool // empty result / success:false / no-op indicator
}

// ExtractEffect classifies a gated request's effect from the request Wardline
// already parsed plus the proxy-visible response signal, and (for write-shaped
// calls) builds the audit Effect.
//
// Write-shaped == a "tools/call" (the only MCP method that can mutate state).
// "resources/*" and "prompts/*" are protocol reads and every non-gated method
// is lifecycle/discovery — both classify as EffectStatusNotAWrite with no
// Effect. Whether a specific *tool* actually mutates is unknowable at the proxy
// without operator config; recording the claimed effect for every tools/call
// is the honest, conservative default.
//
// redact is applied to the captured mutating params — they can carry secrets.
func ExtractEffect(req domain.ParsedRequest, sig EffectSignal, redact func(map[string]string) map[string]string) (*auditdomain.Effect, auditdomain.EffectStatus) {
	if !req.IsToolCall {
		return nil, auditdomain.EffectStatusNotAWrite
	}

	args := shallowParams(req.Call.Params)
	if redact != nil {
		args = redact(args)
	}

	eff := &auditdomain.Effect{
		Target:         req.Call.Tool,
		ClaimedOp:      opName(req),
		ClaimedArgs:    args,
		ResponseStatus: sig.ResponseStatus,
		RPCError:       sig.RPCError,
		NoOpSignal:     sig.NoOpSignal,
	}

	// A proxy can contradict a claimed write (the response signals failure or
	// a no-op) but can rarely *confirm* one — confirmation requires world-state
	// knowledge, which is the Stage-2 verifier's job. So an opaque success is
	// Unconfirmed, never Confirmed.
	status := auditdomain.EffectStatusUnconfirmed
	if sig.RPCError || sig.NoOpSignal || sig.ResponseStatus >= 400 {
		status = auditdomain.EffectStatusContradicted
	}
	return eff, status
}

func opName(req domain.ParsedRequest) string {
	if req.Call.Method != "" {
		return req.Call.Method
	}
	return req.Method
}

// shallowParams parses one level of the JSON-RPC params object into a
// string map for the audit record. Nested/complex values are stringified as
// raw JSON; a non-object body yields an empty map. It never returns nil.
func shallowParams(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return out
	}
	for k, v := range top {
		s := string(v)
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			var unq string
			if json.Unmarshal(v, &unq) == nil {
				s = unq
			}
		}
		out[k] = s
	}
	return out
}
