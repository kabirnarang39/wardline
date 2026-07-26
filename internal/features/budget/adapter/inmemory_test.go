package adapter_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/adapter"
)

func TestInMemoryLimiter_AllowsUpToLimit(t *testing.T) {
	l := adapter.NewInMemoryLimiter(3, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		got := l.Allow("agent-abc123", now)
		if !got.Allowed {
			t.Fatalf("call %d: expected allowed within limit, got %+v", i+1, got)
		}
	}
	got := l.Allow("agent-abc123", now)
	if got.Allowed {
		t.Error("expected the 4th call in the same window to be denied")
	}
}

func TestInMemoryLimiter_ResetsOnNewWindow(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := l.Allow("agent-abc123", now); !got.Allowed {
		t.Fatalf("expected first call allowed, got %+v", got)
	}
	if got := l.Allow("agent-abc123", now); got.Allowed {
		t.Fatal("expected second call in same window denied")
	}

	later := now.Add(time.Minute + time.Second)
	if got := l.Allow("agent-abc123", later); !got.Allowed {
		t.Errorf("expected a call in a new window to be allowed, got %+v", got)
	}
}

func TestInMemoryLimiter_IndependentPerIdentity(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := l.Allow("agent-a", now); !got.Allowed {
		t.Fatalf("expected agent-a's first call allowed, got %+v", got)
	}
	if got := l.Allow("agent-a", now); got.Allowed {
		t.Fatal("expected agent-a's second call denied")
	}
	if got := l.Allow("agent-b", now); !got.Allowed {
		t.Error("expected agent-b's first call to be independently allowed, got denied")
	}
}
