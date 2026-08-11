package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	"github.com/stretchr/testify/assert"
)

func TestConfig_DefaultsWhenUnset(t *testing.T) {
	var c domain.Config
	assert.Equal(t, domain.DefaultRequestsPerJob, c.Limit())
}

func TestConfig_ExplicitValueWins(t *testing.T) {
	c := domain.Config{RequestsPerJob: 42}
	assert.Equal(t, 42, c.Limit())
}

func TestConfig_WindowDefaultsWhenUnset(t *testing.T) {
	var c domain.Config
	assert.Equal(t, domain.DefaultSessionWindowSeconds, c.Window())
}

func TestConfig_WindowExplicitValueWins(t *testing.T) {
	c := domain.Config{SessionWindowSeconds: 60}
	assert.Equal(t, 60, c.Window())
}
