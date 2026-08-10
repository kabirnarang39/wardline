package usecase

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTaintKey_TenantIsolation(t *testing.T) {
	assert.NotEqual(t, taintKey("t1", "alice", "s"), taintKey("t2", "alice", "s"))
}

// A boundary-spoofing pair that a naive concatenation would collide onto one
// key: the length prefix on the (tenant,identity) base keeps them distinct.
func TestTaintKey_NoBoundaryCollision(t *testing.T) {
	assert.NotEqual(t, taintKey("acme", "alice", "x"), taintKey("acme", "alicex", ""))
}
