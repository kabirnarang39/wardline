package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// Recorder builds an Entry from raw call metadata, writes it via the
// configured Writer, and publishes it to sink. Write failures are
// reported through onError and never returned to the caller — a proxy
// must keep serving requests even if the audit sink is unavailable.
// sink may be nil (no live view wired) — Record treats that the same as
// a no-op sink.
type Recorder struct {
	writer  domain.Writer
	sink    domain.LiveSink
	onError func(error)
}

func NewRecorder(w domain.Writer, sink domain.LiveSink, onError func(error)) *Recorder {
	return &Recorder{writer: w, sink: sink, onError: onError}
}

func (r *Recorder) Record(identity, tenantName, tool, decision, reason, traceID string, latency time.Duration, now time.Time) {
	entry := domain.Entry{
		Timestamp: now,
		Identity:  identity,
		Tenant:    tenantName,
		Tool:      tool,
		Decision:  decision,
		LatencyMS: latency.Milliseconds(),
		Reason:    reason,
		TraceID:   traceID,
	}
	if err := r.writer.Write(entry); err != nil && r.onError != nil {
		r.onError(err)
	}
	if r.sink != nil {
		r.sink.Publish(entry)
	}
}
