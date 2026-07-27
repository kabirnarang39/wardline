package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// Recorder builds an Entry from raw call metadata and writes it via the
// configured Writer. Write failures are reported through onError and never
// returned to the caller — a proxy must keep serving requests even if the
// audit sink is unavailable.
type Recorder struct {
	writer  domain.Writer
	onError func(error)
}

func NewRecorder(w domain.Writer, onError func(error)) *Recorder {
	return &Recorder{writer: w, onError: onError}
}

func (r *Recorder) Record(identity, tool, decision, reason, traceID string, latency time.Duration, now time.Time) {
	entry := domain.Entry{
		Timestamp: now,
		Identity:  identity,
		Tool:      tool,
		Decision:  decision,
		LatencyMS: latency.Milliseconds(),
		Reason:    reason,
		TraceID:   traceID,
	}
	if err := r.writer.Write(entry); err != nil && r.onError != nil {
		r.onError(err)
	}
}
