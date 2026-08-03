package adapter_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/adapter"
	"github.com/kabirnarang39/wardline/internal/features/budget/domain"
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

// TestInMemoryLimiter_DefaultLimitReflectsConstructor proves DefaultLimit
// returns exactly what the constructor was given, unaffected by any
// override configured afterward.
func TestInMemoryLimiter_DefaultLimitReflectsConstructor(t *testing.T) {
	l := adapter.NewInMemoryLimiter(25, time.Minute)
	l.SetTenantLimit("acme", 10, 30*time.Second)

	got := l.DefaultLimit()
	want := domain.LimitInfo{RequestsPerWindow: 25, Window: time.Minute}
	if got != want {
		t.Errorf("DefaultLimit() = %+v, want %+v", got, want)
	}
}

// TestInMemoryLimiter_TenantAndToolOverridesReturnSortedSets proves
// TenantOverrides/ToolOverrides return every configured override, sorted
// by name, and an empty slice (not nil) when none are configured.
func TestInMemoryLimiter_TenantAndToolOverridesReturnSortedSets(t *testing.T) {
	l := adapter.NewInMemoryLimiter(25, time.Minute)

	if got := l.TenantOverrides(); len(got) != 0 {
		t.Fatalf("expected no tenant overrides before any are set, got %+v", got)
	}
	if got := l.ToolOverrides(); len(got) != 0 {
		t.Fatalf("expected no tool overrides before any are set, got %+v", got)
	}

	l.SetTenantLimit("widgets-inc", 10, 30*time.Second)
	l.SetTenantLimit("acme", 5, 60*time.Second)
	l.SetToolLimit("run_query", 15, 30*time.Second)

	tenants := l.TenantOverrides()
	want := []domain.OverrideInfo{
		{Scope: "tenant", Name: "acme", LimitInfo: domain.LimitInfo{RequestsPerWindow: 5, Window: 60 * time.Second}},
		{Scope: "tenant", Name: "widgets-inc", LimitInfo: domain.LimitInfo{RequestsPerWindow: 10, Window: 30 * time.Second}},
	}
	if len(tenants) != len(want) || tenants[0] != want[0] || tenants[1] != want[1] {
		t.Errorf("TenantOverrides() = %+v, want %+v (sorted by name)", tenants, want)
	}

	tools := l.ToolOverrides()
	wantTools := []domain.OverrideInfo{
		{Scope: "tool", Name: "run_query", LimitInfo: domain.LimitInfo{RequestsPerWindow: 15, Window: 30 * time.Second}},
	}
	if len(tools) != len(wantTools) || tools[0] != wantTools[0] {
		t.Errorf("ToolOverrides() = %+v, want %+v", tools, wantTools)
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
