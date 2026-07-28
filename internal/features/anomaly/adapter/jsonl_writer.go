package adapter

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

type anomalyJSON struct {
	Timestamp string `json:"timestamp"`
	Identity  string `json:"identity"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
	Tool      string `json:"tool,omitempty"`
	Decision  string `json:"decision,omitempty"`
}

// JSONLWriter writes one JSON object per line to the wrapped io.Writer.
// Anomalies are logged to a separate stream from the audit trail (not a
// variant audit Decision value) -- conflating them would break every
// existing audit-log consumer's assumption that Decision is one of the
// five known values. Safe for concurrent use.
type JSONLWriter struct {
	out io.Writer
	mu  sync.Mutex
}

func NewJSONLWriter(out io.Writer) *JSONLWriter {
	return &JSONLWriter{out: out}
}

func (w *JSONLWriter) Write(a domain.Anomaly) error {
	line, err := json.Marshal(anomalyJSON{
		Timestamp: a.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Identity:  a.Identity,
		Kind:      string(a.Kind),
		Detail:    a.Detail,
		Tool:      a.Entry.Tool,
		Decision:  a.Entry.Decision,
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
