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
type InMemoryLimiter struct {
	requestsPerWindow int
	window            time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

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
