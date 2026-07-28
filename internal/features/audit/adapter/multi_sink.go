package adapter

import "github.com/kabirnarang39/wardline/internal/features/audit/domain"

// MultiSink fans Publish out to every member, in order. A nil member is
// skipped rather than panicking, so a caller can build the slice with an
// optional member left as nil (e.g. "only add the anomaly detector when
// the feature flag is on") without a separate compaction step. Each
// member is already required to honor domain.LiveSink's contract (never
// block, never error outward), so MultiSink itself adds no error
// handling of its own -- it is exactly as safe as its least safe member,
// which is a property every existing LiveSink implementation already
// guarantees.
type MultiSink []domain.LiveSink

func (m MultiSink) Publish(e domain.Entry) {
	for _, sink := range m {
		if sink == nil {
			continue
		}
		sink.Publish(e)
	}
}
