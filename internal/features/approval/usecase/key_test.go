package usecase

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrantKey_IsolatesTenantSessionTool(t *testing.T) {
	base := grantKey("acme", "alice", "s1", "delete")
	assert.NotEqual(t, base, grantKey("other", "alice", "s1", "delete"))
	assert.NotEqual(t, base, grantKey("acme", "alice", "s2", "delete"))
	assert.NotEqual(t, base, grantKey("acme", "alice", "s1", "read"))
	// boundary spoof: length prefixes keep these distinct
	assert.NotEqual(t, grantKey("acme", "alice", "x", "t"), grantKey("acme", "alicex", "", "t"))
}
