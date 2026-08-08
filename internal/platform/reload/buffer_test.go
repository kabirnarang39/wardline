package reload_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

func TestReloadEventBuffer_CapsAtCapacityDroppingOldest(t *testing.T) {
	buf := reload.NewReloadEventBuffer(2)
	buf.Add(reload.ReloadResult{Domain: "policy", Timestamp: time.Unix(1, 0)})
	buf.Add(reload.ReloadResult{Domain: "rbac", Timestamp: time.Unix(2, 0)})
	buf.Add(reload.ReloadResult{Domain: "budget", Timestamp: time.Unix(3, 0)})

	got := buf.Since(0, 10)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (capacity-capped)", len(got))
	}
	if got[0].Domain != "rbac" || got[1].Domain != "budget" {
		t.Errorf("expected the oldest (policy) to be evicted, got %+v", got)
	}
}

func TestReloadEventBuffer_SinceFromStartReturnsEverything(t *testing.T) {
	b := reload.NewReloadEventBuffer(10)
	b.Add(reload.ReloadResult{Domain: "policy"})
	b.Add(reload.ReloadResult{Domain: "rbac"})

	got := b.Since(0, 0)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestReloadEventBuffer_SinceReturnsOnlyNewerEntries(t *testing.T) {
	b := reload.NewReloadEventBuffer(10)
	b.Add(reload.ReloadResult{Domain: "policy"})
	b.Add(reload.ReloadResult{Domain: "rbac"})

	first := b.Since(0, 0)[0]
	got := b.Since(first.ID, 0)
	if len(got) != 1 || got[0].Domain != "rbac" {
		t.Fatalf("expected only rbac's entry after the first ID, got %+v", got)
	}
}

func TestReloadEventBuffer_LimitCapsResultToMostRecent(t *testing.T) {
	b := reload.NewReloadEventBuffer(10)
	b.Add(reload.ReloadResult{Domain: "one"})
	b.Add(reload.ReloadResult{Domain: "two"})
	b.Add(reload.ReloadResult{Domain: "three"})

	got := b.Since(0, 2)
	if len(got) != 2 || got[0].Domain != "two" || got[1].Domain != "three" {
		t.Fatalf("expected the 2 most recent entries, got %+v", got)
	}
}

func TestReloadEventBuffer_AfterIDAheadOfNextIDTreatedAsFromStart(t *testing.T) {
	b := reload.NewReloadEventBuffer(10)
	b.Add(reload.ReloadResult{Domain: "policy"})

	got := b.Since(999, 0)
	if len(got) != 1 {
		t.Fatalf("expected an afterID ahead of nextID to reset to \"from start\", got %d entries", len(got))
	}
}
