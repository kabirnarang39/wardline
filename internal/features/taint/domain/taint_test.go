package domain_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/taint/domain"
	"github.com/stretchr/testify/assert"
)

func TestLabel_ZeroValueIsUntainted(t *testing.T) {
	var l domain.Label
	assert.False(t, l.Tainted)
	assert.True(t, l.SetAt.IsZero())
	assert.Nil(t, l.Sources)
}

func TestLabel_SetReportsTainted(t *testing.T) {
	now := time.Now()
	l := domain.Label{Tainted: true, SetAt: now, Sources: []string{"untrusted_fetch"}}
	assert.True(t, l.Tainted)
	assert.Equal(t, now, l.SetAt)
	assert.Equal(t, []string{"untrusted_fetch"}, l.Sources)
}
