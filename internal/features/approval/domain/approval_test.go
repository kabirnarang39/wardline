package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
)

func TestRequest_ZeroValueIsUnset(t *testing.T) {
	var r domain.Request
	assert.Equal(t, domain.Status(""), r.Status)
	assert.Equal(t, "pending", string(domain.StatusPending))
	assert.Equal(t, "approved", string(domain.StatusApproved))
	assert.Equal(t, "denied", string(domain.StatusDenied))
}
