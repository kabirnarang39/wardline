package adapter

import "github.com/kabirnarang39/wardline/internal/features/audit/domain"

// NoopSink is a domain.LiveSink that discards every entry. Wired in when
// the web_ui feature flag is off, so Recorder.Record never has to branch
// on the flag itself — same reasoning as tracing.NewDisabled's no-op
// tracer.
type NoopSink struct{}

func (NoopSink) Publish(domain.Entry) {}
