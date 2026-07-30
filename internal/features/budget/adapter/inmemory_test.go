package adapter_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/adapter"
)

func TestInMemoryLimiter_AllowsUpToLimit(t *testing.T) {
	l := adapter.NewInMemoryLimiter(3, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		got := l.Allow("agent-abc123", "", now)
		if !got.Allowed {
			t.Fatalf("call %d: expected allowed within limit, got %+v", i+1, got)
		}
	}
	got := l.Allow("agent-abc123", "", now)
	if got.Allowed {
		t.Error("expected the 4th call in the same window to be denied")
	}
}

func TestInMemoryLimiter_ResetsOnNewWindow(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := l.Allow("agent-abc123", "", now); !got.Allowed {
		t.Fatalf("expected first call allowed, got %+v", got)
	}
	if got := l.Allow("agent-abc123", "", now); got.Allowed {
		t.Fatal("expected second call in same window denied")
	}

	later := now.Add(time.Minute + time.Second)
	if got := l.Allow("agent-abc123", "", later); !got.Allowed {
		t.Errorf("expected a call in a new window to be allowed, got %+v", got)
	}
}

func TestInMemoryLimiter_IndependentPerIdentity(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := l.Allow("agent-a", "", now); !got.Allowed {
		t.Fatalf("expected agent-a's first call allowed, got %+v", got)
	}
	if got := l.Allow("agent-a", "", now); got.Allowed {
		t.Fatal("expected agent-a's second call denied")
	}
	if got := l.Allow("agent-b", "", now); !got.Allowed {
		t.Error("expected agent-b's first call to be independently allowed, got denied")
	}
}

// TestInMemoryLimiter_TenantOverrideThrottlesIndependentlyOfIdentity proves
// the core new behavior of the tenant override: a tenant bucket denies a
// request even when the calling identity is nowhere near its own (generous)
// identity-level limit, and a tenant with no override is unaffected.
func TestInMemoryLimiter_TenantOverrideThrottlesIndependentlyOfIdentity(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1000, time.Minute) // generous global identity default
	l.SetTenantLimit("acme", 1, time.Minute)            // acme tenant capped at 1 request/window

	now := time.Now()
	if v := l.Allow("alice", "acme", now); !v.Allowed {
		t.Fatal("first call in acme should be allowed")
	}
	if v := l.Allow("bob", "acme", now); v.Allowed {
		t.Fatal("second distinct identity in the SAME over-limit tenant should be throttled by the tenant bucket")
	}
	if v := l.Allow("carol", "widgets-inc", now); !v.Allowed {
		t.Fatal("a different tenant with no override should be unaffected by acme's limit")
	}
}

// TestInMemoryLimiter_ConcurrentAccessIsSafe proves the limiter is safe
// under contention (run with -race to catch data races) and doesn't
// over-admit: with requestsPerWindow=10, exactly 10 of 50 concurrent
// callers for the same identity should be allowed, never more.
func TestInMemoryLimiter_ConcurrentAccessIsSafe(t *testing.T) {
	const goroutines = 50
	const requestsPerWindow = 10

	l := adapter.NewInMemoryLimiter(requestsPerWindow, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if got := l.Allow("agent-abc123", "", now); got.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	if allowed != requestsPerWindow {
		t.Errorf("expected exactly %d allowed calls out of %d concurrent callers, got %d", requestsPerWindow, goroutines, allowed)
	}
}
