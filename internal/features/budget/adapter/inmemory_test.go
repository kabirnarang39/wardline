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
		got := l.Allow("agent-abc123", "", "", now)
		if !got.Allowed {
			t.Fatalf("call %d: expected allowed within limit, got %+v", i+1, got)
		}
	}
	got := l.Allow("agent-abc123", "", "", now)
	if got.Allowed {
		t.Error("expected the 4th call in the same window to be denied")
	}
}

func TestInMemoryLimiter_ResetsOnNewWindow(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := l.Allow("agent-abc123", "", "", now); !got.Allowed {
		t.Fatalf("expected first call allowed, got %+v", got)
	}
	if got := l.Allow("agent-abc123", "", "", now); got.Allowed {
		t.Fatal("expected second call in same window denied")
	}

	later := now.Add(time.Minute + time.Second)
	if got := l.Allow("agent-abc123", "", "", later); !got.Allowed {
		t.Errorf("expected a call in a new window to be allowed, got %+v", got)
	}
}

func TestInMemoryLimiter_IndependentPerIdentity(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if got := l.Allow("agent-a", "", "", now); !got.Allowed {
		t.Fatalf("expected agent-a's first call allowed, got %+v", got)
	}
	if got := l.Allow("agent-a", "", "", now); got.Allowed {
		t.Fatal("expected agent-a's second call denied")
	}
	if got := l.Allow("agent-b", "", "", now); !got.Allowed {
		t.Error("expected agent-b's first call to be independently allowed, got denied")
	}
}

// TestInMemoryLimiter_TenantOverrideThrottlesIndependentlyOfIdentity proves
// the core new behavior of the tenant override: a tenant bucket denies a
// request even when the calling identity is nowhere near its own (generous)
// identity-level limit, and a tenant with no override is unaffected.
func TestInMemoryLimiter_TenantOverrideThrottlesIndependentlyOfIdentity(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1000, time.Minute) // generous global identity default
	l.SetTenantLimit("acme", 1, time.Minute)           // acme tenant capped at 1 request/window

	now := time.Now()
	if v := l.Allow("alice", "acme", "", now); !v.Allowed {
		t.Fatal("first call in acme should be allowed")
	}
	if v := l.Allow("bob", "acme", "", now); v.Allowed {
		t.Fatal("second distinct identity in the SAME over-limit tenant should be throttled by the tenant bucket")
	}
	if v := l.Allow("carol", "widgets-inc", "", now); !v.Allowed {
		t.Fatal("a different tenant with no override should be unaffected by acme's limit")
	}
}

// TestInMemoryLimiter_IdentityBucketIsPerTenant is an I1 regression test:
// the identity bucket used to be keyed by bare identity, so two tenants'
// same-named identities (e.g. two different IdPs both provisioning
// "alice") shared one rate-limit bucket, and either tenant could deny
// service to the other's identically-named identity by exhausting its
// own budget.
func TestInMemoryLimiter_IdentityBucketIsPerTenant(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if v := l.Allow("alice", "acme", "", now); !v.Allowed {
		t.Fatal("acme's alice first call should be allowed")
	}
	if v := l.Allow("alice", "acme", "", now); v.Allowed {
		t.Fatal("acme's alice second call in the same window should be denied")
	}

	// widgets-inc's alice must be independently allowed -- before the
	// fix, this call was denied by acme's alice's identity bucket.
	if v := l.Allow("alice", "widgets-inc", "", now); !v.Allowed {
		t.Fatal("widgets-inc's alice should not be throttled by acme's alice's identity bucket")
	}
}

// TestInMemoryLimiter_ToolOverrideThrottlesIndependentlyOfIdentityAndTenant
// proves the core new behavior of the tool override: a tool bucket denies a
// request even when the calling identity/tenant are nowhere near their own
// (generous) limits, and a tool with no override is unaffected.
func TestInMemoryLimiter_ToolOverrideThrottlesIndependentlyOfIdentityAndTenant(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	l := adapter.NewInMemoryLimiter(1000, time.Minute) // generous identity default
	l.SetToolLimit("expensive_tool", 1, time.Minute)

	// First call to the expensive tool from alice: allowed, exhausts the tool bucket.
	v := l.Allow("alice", "acme", "expensive_tool", now)
	if !v.Allowed {
		t.Fatal("expected first call to expensive_tool to be allowed")
	}

	// A DIFFERENT identity calling the SAME tool is throttled by the
	// shared tool bucket, even though bob is nowhere near his own
	// identity-level limit.
	v = l.Allow("bob", "acme", "expensive_tool", now)
	if v.Allowed {
		t.Error("expected bob's call to expensive_tool to be throttled by the shared tool bucket")
	}

	// alice calling a DIFFERENT, unconfigured tool is unaffected.
	v = l.Allow("alice", "acme", "cheap_tool", now)
	if !v.Allowed {
		t.Error("expected a tool with no override to be unaffected by expensive_tool's bucket")
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
			if got := l.Allow("agent-abc123", "", "", now); got.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	if allowed != requestsPerWindow {
		t.Errorf("expected exactly %d allowed calls out of %d concurrent callers, got %d", requestsPerWindow, goroutines, allowed)
	}
}

// TestInMemoryLimiter_SetDefaultLimit_UpdatesThresholdWithoutResettingCounters
// is the load-bearing proof that a budget reload updates the limiter IN
// PLACE rather than reconstructing it: reconstructing would zero every
// identity's live count, letting a caller briefly burst past their real
// limit at the exact moment of reload.
func TestInMemoryLimiter_SetDefaultLimit_UpdatesThresholdWithoutResettingCounters(t *testing.T) {
	l := adapter.NewInMemoryLimiter(2, time.Minute) // 2 requests per minute
	now := time.Now()

	// Consume the full default budget for identity "alice".
	l.Allow("alice", "", "", now)
	l.Allow("alice", "", "", now)
	if v := l.Allow("alice", "", "", now); v.Allowed {
		t.Fatalf("expected 3rd call to be denied before any reload")
	}

	// Reload: raise the default limit to 5.
	l.SetDefaultLimit(5, time.Minute)

	// alice's ALREADY-CONSUMED 2 requests must still count -- she should
	// get 3 more allowed calls (5 total), not 5 fresh ones. This is the
	// assertion that would fail if a reload reconstructed the limiter
	// instead of updating it in place.
	allowedAfterReload := 0
	for i := 0; i < 5; i++ {
		if l.Allow("alice", "", "", now).Allowed {
			allowedAfterReload++
		}
	}
	if allowedAfterReload != 3 {
		t.Errorf("allowed %d more calls after raising the limit to 5 with 2 already consumed, want exactly 3", allowedAfterReload)
	}
}

// TestInMemoryLimiter_ClearTenantLimit_RevertsToGlobalDefault proves a
// tenant override removed by a reload (present in the OLD config, absent
// from the new one) actually stops being enforced, rather than surviving
// as a stale leftover forever -- SetTenantLimit alone can only add or
// update an override, never remove one.
func TestInMemoryLimiter_ClearTenantLimit_RevertsToGlobalDefault(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1000, time.Minute) // generous global default
	l.SetTenantLimit("acme", 1, time.Minute)
	now := time.Now()

	if v := l.Allow("alice", "acme", "", now); !v.Allowed {
		t.Fatal("first call in acme should be allowed")
	}
	if v := l.Allow("bob", "acme", "", now); v.Allowed {
		t.Fatal("second distinct identity in the SAME over-limit tenant should be throttled by the tenant override")
	}

	l.ClearTenantLimit("acme")

	// acme now falls through to the generous global default -- bob's call,
	// previously denied by the tenant bucket, must now be admitted.
	if v := l.Allow("bob", "acme", "", now); !v.Allowed {
		t.Fatal("expected acme to revert to the global default after ClearTenantLimit, but it's still throttled")
	}
}

// TestInMemoryLimiter_ClearToolLimit_RevertsToGlobalDefault mirrors
// TestInMemoryLimiter_ClearTenantLimit_RevertsToGlobalDefault exactly, for
// the tool-tier override.
func TestInMemoryLimiter_ClearToolLimit_RevertsToGlobalDefault(t *testing.T) {
	l := adapter.NewInMemoryLimiter(1000, time.Minute) // generous global default
	l.SetToolLimit("expensive_tool", 1, time.Minute)
	now := time.Now()

	if v := l.Allow("alice", "acme", "expensive_tool", now); !v.Allowed {
		t.Fatal("first call to expensive_tool should be allowed")
	}
	if v := l.Allow("bob", "widgets-inc", "expensive_tool", now); v.Allowed {
		t.Fatal("second call to the SAME over-limit tool should be throttled by the tool override")
	}

	l.ClearToolLimit("expensive_tool")

	if v := l.Allow("bob", "widgets-inc", "expensive_tool", now); !v.Allowed {
		t.Fatal("expected expensive_tool to revert to the global default after ClearToolLimit, but it's still throttled")
	}
}
