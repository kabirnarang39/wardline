package session_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/session"
	"github.com/stretchr/testify/assert"
)

var t0 = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

func TestSessionID_HeaderWins(t *testing.T) {
	assert.Equal(t, "sess-abc", session.SessionID("sess-abc", "acme", "alice", t0, 300))
}

func TestSessionID_WindowFallback(t *testing.T) {
	a := session.SessionID("", "acme", "alice", t0, 300)
	b := session.SessionID("", "acme", "alice", t0.Add(200*time.Second), 300)
	c := session.SessionID("", "acme", "alice", t0.Add(400*time.Second), 300)
	assert.Equal(t, a, b)    // same window
	assert.NotEqual(t, a, c) // next window
}
