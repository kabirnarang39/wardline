package usecase

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type noopWriter struct{}

func (noopWriter) Write(domain.Anomaly) error { return nil }

func TestDetector_GC_DropsStaleStateKeepsFreshState(t *testing.T) {
	base := time.Unix(0, 0)
	cur := base
	cfg := domain.HeuristicConfig{WindowSeconds: 60}
	d := NewDetector(cfg, noopWriter{}, nil, nil, func() time.Time { return cur })

	d.Publish(auditdomain.Entry{Identity: "stale-identity", Tool: "read_file", Decision: "allow"})
	cur = base.Add(5 * time.Minute)
	d.Publish(auditdomain.Entry{Identity: "fresh-identity", Tool: "read_file", Decision: "allow"})

	// GC with a 2-minute interval means anything not seen in the last 4
	// minutes (2x interval) is dropped -- stale-identity (last seen at
	// t=0, now t=5m) qualifies; fresh-identity (last seen at t=5m) does not.
	d.gc(cur, 2*time.Minute)

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.state["stale-identity"]; ok {
		t.Error("expected stale-identity's state to be evicted")
	}
	if _, ok := d.state["fresh-identity"]; !ok {
		t.Error("expected fresh-identity's state to survive the GC pass")
	}
}
