package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
	"github.com/stretchr/testify/assert"
)

func TestApprovalConfig_DefaultsWhenUnset(t *testing.T) {
	var c domain.Config
	assert.Equal(t, domain.DefaultGrantTTLSeconds, c.GrantTTL())
}

func TestApprovalConfig_ExplicitValuesWin(t *testing.T) {
	c := domain.Config{GrantTTLSeconds: 600}
	assert.Equal(t, 600, c.GrantTTL())
}
