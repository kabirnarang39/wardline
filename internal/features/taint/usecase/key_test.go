package usecase

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var t0 = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

func TestSessionID_HeaderWins(t *testing.T) {
	assert.Equal(t, "sess-abc", SessionID("sess-abc", "acme", "alice", t0, 300))
}

func TestSessionID_WindowFallback(t *testing.T) {
	a := SessionID("", "acme", "alice", t0, 300)
	b := SessionID("", "acme", "alice", t0.Add(200*time.Second), 300)
	c := SessionID("", "acme", "alice", t0.Add(400*time.Second), 300)
	assert.Equal(t, a, b)    // same window
	assert.NotEqual(t, a, c) // next window
}

func TestTaintKey_TenantIsolation(t *testing.T) {
	assert.NotEqual(t, taintKey("t1", "alice", "s"), taintKey("t2", "alice", "s"))
}

// A boundary-spoofing pair that a naive concatenation would collide onto one
// key: the length prefix on the (tenant,identity) base keeps them distinct.
func TestTaintKey_NoBoundaryCollision(t *testing.T) {
	assert.NotEqual(t, taintKey("acme", "alice", "x"), taintKey("acme", "alicex", ""))
}
