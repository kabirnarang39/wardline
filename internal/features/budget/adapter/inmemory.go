package adapter

import (
	"fmt"
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/budget/domain"
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

	mu      sync.Mutex
	buckets map[string]*bucket
	calls   uint64
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
	}
}

func (l *InMemoryLimiter) Allow(identity string, now time.Time) domain.Verdict {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%evictionSweepInterval == 0 {
		l.evictExpired(now)
	}

	b, ok := l.buckets[identity]
	if !ok || now.Sub(b.windowStart) >= l.window {
		b = &bucket{windowStart: now, count: 0}
		l.buckets[identity] = b
	}

	if b.count >= l.requestsPerWindow {
		return domain.Verdict{
			Allowed: false,
			Reason:  fmt.Sprintf("rate limit exceeded: %d requests per %s window", l.requestsPerWindow, l.window),
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
}
