package metrics_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/metrics"
)

func TestNewDisabled_ObserveRequestIsSafeNoOp(t *testing.T) {
	r := metrics.NewDisabled()
	// Must not panic regardless of input -- this is the default every
	// Handler gets unless features.prometheus_metrics is on.
	r.ObserveRequest("allow", 5*time.Millisecond)
	r.ObserveRequest("", -1)
}
