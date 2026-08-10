package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

func TestEntry_EffectDefaults(t *testing.T) {
	var e domain.Entry
	assert.Nil(t, e.Effect)
	assert.Equal(t, domain.EffectStatus(""), e.EffectStatus)
}

func TestEffectStatus_Values(t *testing.T) {
	assert.Equal(t, "claimed_and_confirmed", string(domain.EffectStatusConfirmed))
	assert.Equal(t, "claimed_but_unconfirmed", string(domain.EffectStatusUnconfirmed))
	assert.Equal(t, "claimed_but_contradicted", string(domain.EffectStatusContradicted))
	assert.Equal(t, "not_a_write", string(domain.EffectStatusNotAWrite))
}

func TestVerdict_Values(t *testing.T) {
	assert.Equal(t, "confirmed", string(domain.VerdictConfirmed))
	assert.Equal(t, "contradicted", string(domain.VerdictContradicted))
	assert.Equal(t, "unknown", string(domain.VerdictUnknown))
}
