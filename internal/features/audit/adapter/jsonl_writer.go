package adapter

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type entryJSON struct {
	Timestamp    string      `json:"timestamp"`
	Identity     string      `json:"identity"`
	Tenant       string      `json:"tenant,omitempty"`
	Tool         string      `json:"tool"`
	Decision     string      `json:"decision"`
	LatencyMS    int64       `json:"latency_ms"`
	Reason       string      `json:"reason,omitempty"`
	TraceID      string      `json:"trace_id,omitempty"`
	Effect       *effectJSON `json:"effect,omitempty"`
	EffectStatus string      `json:"effect_status,omitempty"`
	SessionID    string      `json:"session_id,omitempty"`
}

type effectJSON struct {
	Target         string            `json:"target,omitempty"`
	ClaimedOp      string            `json:"claimed_op,omitempty"`
	ClaimedArgs    map[string]string `json:"claimed_args,omitempty"`
	ResponseStatus int               `json:"response_status,omitempty"`
	RPCError       bool              `json:"rpc_error,omitempty"`
	NoOpSignal     bool              `json:"no_op_signal,omitempty"`
}

func toEffectJSON(e *domain.Effect) *effectJSON {
	if e == nil {
		return nil
	}
	return &effectJSON{
		Target:         e.Target,
		ClaimedOp:      e.ClaimedOp,
		ClaimedArgs:    e.ClaimedArgs,
		ResponseStatus: e.ResponseStatus,
		RPCError:       e.RPCError,
		NoOpSignal:     e.NoOpSignal,
	}
}

// JSONLWriter writes one JSON object per line to the wrapped io.Writer.
// Safe for concurrent use.
type JSONLWriter struct {
	out io.Writer
	mu  sync.Mutex
}

func NewJSONLWriter(out io.Writer) *JSONLWriter {
	return &JSONLWriter{out: out}
}

func (w *JSONLWriter) Write(e domain.Entry) error {
	line, err := json.Marshal(entryJSON{
		Timestamp:    e.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Identity:     e.Identity,
		Tenant:       e.Tenant,
		Tool:         e.Tool,
		Decision:     e.Decision,
		LatencyMS:    e.LatencyMS,
		Reason:       e.Reason,
		TraceID:      e.TraceID,
		Effect:       toEffectJSON(e.Effect),
		EffectStatus: string(e.EffectStatus),
		SessionID:    e.SessionID,
	})
	if err != nil {
		return err
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.out.Write(line)
	return err
}
