package adapter

import (
	"fmt"
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// bucket tracks one identity's fixed-window request count.
type bucket struct {
	windowStart time.Time
	count       int
}

// InMemoryLimiter is a domain.Limiter backed by a per-identity fixed-window
// counter held in process memory. Correct for a single wardline process;
// running multiple replicas gives each its own independent budget — a
// known limitation, not a bug, until a shared-state backend exists.
//
// Identity is trusted as-is: the X-Wardline-Identity header carries it
// through, unauthenticated. Nothing here validates it, so buckets is keyed
// by whatever a caller sends — a caller that rotates identity values can
// evade rate limiting entirely (see README.md "Budget enforcement"). The
// evictionSweepInterval below exists specifically because an unbounded
// stream of distinct identities would otherwise grow buckets forever.
type InMemoryLimiter struct {
	requestsPerWindow int
	window            time.Duration

	mu sync.Mutex
	// buckets is keyed by tenant.Key(tenant, identity), not by bare
	// identity -- two tenants' same-named identities (e.g. two IdPs both
	// provisioning "alice") must not share a rate-limit bucket. See
	// tenant.Key's doc comment.
	buckets map[string]*bucket
	calls   uint64

	// tenantLimits and tenantBuckets back the optional per-tenant override:
	// a tenant with no entry in tenantLimits is simply not checked, so a
	// deployment that never calls SetTenantLimit behaves exactly as before.
	tenantLimits  map[string]tenantLimit
	tenantBuckets map[string]*bucket

	// toolLimits and toolBuckets back the optional per-tool override, same
	// shape and same "unset means unchecked" semantics as tenantLimits
	// above. Keyed by bare tool name (NOT tenant+tool): a tool's limit
	// applies globally across every identity/tenant calling it, mirroring
	// how a tenant's limit applies across all of that tenant's identities.
	toolLimits  map[string]tenantLimit
	toolBuckets map[string]*bucket
}

// tenantLimit is a tenant's override rate, set via SetTenantLimit.
type tenantLimit struct {
	requestsPerWindow int
	window            time.Duration
}

// evictionSweepInterval is how many Allow calls pass between opportunistic
// sweeps of expired buckets. 1000 is arbitrary but cheap: a full map scan
// every 1000 calls is negligible next to per-call work, and bounds memory
// growth from identity churn without a background goroutine or scheduler.
//
// ponytail: inline sweep piggybacking on Allow, not a dedicated cleanup
// goroutine — keeps the existing single-mutex design simple. If identity
// cardinality gets high enough that a 1000-call-wide sweep window isn't
// tight enough, a background sweeper is the upgrade path.
const evictionSweepInterval = 1000

func NewInMemoryLimiter(requestsPerWindow int, window time.Duration) *InMemoryLimiter {
	return &InMemoryLimiter{
		requestsPerWindow: requestsPerWindow,
		window:            window,
		buckets:           make(map[string]*bucket),
		tenantLimits:      make(map[string]tenantLimit),
		tenantBuckets:     make(map[string]*bucket),
		toolLimits:        make(map[string]tenantLimit),
		toolBuckets:       make(map[string]*bucket),
	}
}

// SetTenantLimit configures an override rate for tenantName, consulted
// alongside (in addition to, not instead of) the identity bucket. A tenant
// with no override configured here is never checked against a tenant
// bucket at all — Allow falls straight through to the identity check.
func (l *InMemoryLimiter) SetTenantLimit(tenantName string, requestsPerWindow int, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tenantLimits[tenantName] = tenantLimit{requestsPerWindow: requestsPerWindow, window: window}
}

// SetToolLimit configures an override rate for toolName, consulted alongside
// (in addition to, not instead of) the identity and tenant buckets -- mirrors
// SetTenantLimit exactly. A tool with no override configured here is never
// checked against a tool bucket at all.
func (l *InMemoryLimiter) SetToolLimit(toolName string, requestsPerWindow int, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.toolLimits[toolName] = tenantLimit{requestsPerWindow: requestsPerWindow, window: window}
}

// Allow requires the identity bucket, the tenant bucket (if tenant has a
// configured override), AND the tool bucket (if tool has a configured
// override) to all admit the request -- an AND, not an OR. The tool check
// runs first (cheapest to fail fast on a hot, narrow tool), then tenant,
// then identity -- a request denied by an earlier check never consumes a
// later, lower-priority bucket's budget.
func (l *InMemoryLimiter) Allow(identity, tenantName, toolName string, now time.Time) domain.Verdict {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%evictionSweepInterval == 0 {
		l.evictExpired(now)
	}

	if limit, ok := l.toolLimits[toolName]; ok {
		tb, exists := l.toolBuckets[toolName]
		if !exists {
			tb = &bucket{}
			l.toolBuckets[toolName] = tb
		}
		if v := checkAndAdvance(tb, limit.requestsPerWindow, limit.window, now); !v.Allowed {
			return v
		}
	}

	if limit, ok := l.tenantLimits[tenantName]; ok {
		tb, exists := l.tenantBuckets[tenantName]
		if !exists {
			tb = &bucket{}
			l.tenantBuckets[tenantName] = tb
		}
		if v := checkAndAdvance(tb, limit.requestsPerWindow, limit.window, now); !v.Allowed {
			return v
		}
	}

	key := tenant.Key(tenantName, identity)
	ib, exists := l.buckets[key]
	if !exists {
		ib = &bucket{}
		l.buckets[key] = ib
	}
	return checkAndAdvance(ib, l.requestsPerWindow, l.window, now)
}

// checkAndAdvance is the fixed-window check-and-increment shared by both the
// identity and tenant buckets: reset the window if it's expired, deny if
// already at capacity, otherwise increment and admit.
func checkAndAdvance(b *bucket, requestsPerWindow int, window time.Duration, now time.Time) domain.Verdict {
	if b.windowStart.IsZero() || now.Sub(b.windowStart) >= window {
		b.windowStart = now
		b.count = 0
	}

	if b.count >= requestsPerWindow {
		return domain.Verdict{
			Allowed:    false,
			Reason:     fmt.Sprintf("rate limit exceeded: %d requests per %s window", requestsPerWindow, window),
			RetryAfter: b.windowStart.Add(window).Sub(now),
		}
	}
	b.count++
	return domain.Verdict{Allowed: true, Reason: "within budget"}
}

// evictExpired deletes buckets whose window has already lapsed. Called with
// l.mu already held.
func (l *InMemoryLimiter) evictExpired(now time.Time) {
	for id, b := range l.buckets {
		if now.Sub(b.windowStart) >= l.window {
			delete(l.buckets, id)
		}
	}
	for name, b := range l.tenantBuckets {
		if now.Sub(b.windowStart) >= l.tenantLimits[name].window {
			delete(l.tenantBuckets, name)
		}
	}
	for name, b := range l.toolBuckets {
		if now.Sub(b.windowStart) >= l.toolLimits[name].window {
			delete(l.toolBuckets, name)
		}
	}
}
