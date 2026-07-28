package adapter

import "github.com/kabirnarang39/wardline/internal/features/audit/domain"

// MultiSink fans Publish out to every member, in order. Each member is
// already required to honor domain.LiveSink's contract (never block,
// never error outward), so MultiSink adds no error handling of its own --
// it is exactly as safe as its least safe member, which is a property
// every existing LiveSink implementation already guarantees.
//
// A nil *interface* member is skipped rather than panicking. That is NOT
// a licence to build the slice from optional concrete pointers: a nil
// *anomalyusecase.Detector stored in a domain.LiveSink slot is a typed
// nil, which is not == nil, so it is dispatched to and panics on first
// use. Decide membership before constructing the slice -- see the
// exhaustive feature-flag switch in cmd/wardline/main.go's runServe,
// which only ever puts already-constructed sinks in here.
type MultiSink []domain.LiveSink

func (m MultiSink) Publish(e domain.Entry) {
	for _, sink := range m {
		if sink == nil {
			continue
		}
		sink.Publish(e)
	}
}
