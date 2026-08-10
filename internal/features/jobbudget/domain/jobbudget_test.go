package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	"github.com/stretchr/testify/assert"
)

func TestVerdict_ZeroValueIsUnset(t *testing.T) {
	var v domain.Verdict
	assert.False(t, v.Allowed)
	assert.Equal(t, 0, v.Count)
	assert.False(t, v.FailedOpen)
}
