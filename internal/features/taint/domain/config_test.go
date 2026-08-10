package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/taint/domain"
	"github.com/stretchr/testify/assert"
)

func TestTaintConfig_DefaultsWhenUnset(t *testing.T) {
	var c domain.TaintConfig
	assert.Equal(t, domain.DefaultTTLSeconds, c.TTL())
	assert.Equal(t, domain.DefaultSessionWindowSeconds, c.Window())
	assert.Equal(t, domain.DefaultSessionHeader, c.Header())
}

func TestTaintConfig_ExplicitValuesWin(t *testing.T) {
	c := domain.TaintConfig{TTLSeconds: 120, SessionWindowSeconds: 60, SessionHeader: "X-Session"}
	assert.Equal(t, 120, c.TTL())
	assert.Equal(t, 60, c.Window())
	assert.Equal(t, "X-Session", c.Header())
}
