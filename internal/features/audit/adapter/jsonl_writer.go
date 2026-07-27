package adapter

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type entryJSON struct {
	Timestamp string `json:"timestamp"`
	Identity  string `json:"identity"`
	Tool      string `json:"tool"`
	Decision  string `json:"decision"`
	LatencyMS int64  `json:"latency_ms"`
	Reason    string `json:"reason,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
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
		Timestamp: e.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Identity:  e.Identity,
		Tool:      e.Tool,
		Decision:  e.Decision,
		LatencyMS: e.LatencyMS,
		Reason:    e.Reason,
		TraceID:   e.TraceID,
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
