package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
	"github.com/stretchr/testify/assert"
)

func TestConfig_LimitDefaultsWhenUnset(t *testing.T) {
	var c domain.Config
	assert.Equal(t, domain.DefaultCeiling, c.Limit())
}

func TestConfig_LimitExplicitValueWins(t *testing.T) {
	c := domain.Config{Ceiling: 42}
	assert.Equal(t, 42, c.Limit())
}

func TestConfig_CostOf_DeclaredToolWins(t *testing.T) {
	c := domain.Config{ToolCosts: map[string]int{"llm_call": 50}}
	assert.Equal(t, 50, c.CostOf("llm_call"))
}

func TestConfig_CostOf_ExplicitZeroIsHonored(t *testing.T) {
	c := domain.Config{ToolCosts: map[string]int{"free_tool": 0}, DefaultCost: 5}
	assert.Equal(t, 0, c.CostOf("free_tool"))
}

func TestConfig_CostOf_UndeclaredToolUsesDefaultCost(t *testing.T) {
	c := domain.Config{DefaultCost: 5}
	assert.Equal(t, 5, c.CostOf("anything"))
}

func TestConfig_CostOf_UndeclaredToolAndUnsetDefaultUsesBuiltinDefault(t *testing.T) {
	var c domain.Config
	assert.Equal(t, domain.DefaultToolCost, c.CostOf("anything"))
}
