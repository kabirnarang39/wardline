package adapter_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

func TestNoopSink_PublishDoesNotPanic(t *testing.T) {
	var sink domain.LiveSink = adapter.NoopSink{}
	sink.Publish(domain.Entry{Identity: "agent-1", Timestamp: time.Now()})
}
