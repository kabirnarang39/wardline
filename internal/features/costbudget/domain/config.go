package domain

// Config is the cost budget's own (yaml-free) configuration.
type Config struct {
	Ceiling int // <=0 uses DefaultCeiling

	// ToolCosts declares each tool's per-call cost. A tool absent from
	// this map uses DefaultCost -- an explicit 0 for a declared tool is
	// honored (a genuinely free tool), never treated as "unset".
	ToolCosts map[string]int

	// DefaultCost is the cost for a tool not present in ToolCosts. <=0
	// uses DefaultToolCost.
	DefaultCost int
}

const DefaultCeiling = 1000
const DefaultToolCost = 1

// Limit returns the configured ceiling, or the default when unset.
func (c Config) Limit() int {
	if c.Ceiling <= 0 {
		return DefaultCeiling
	}
	return c.Ceiling
}

// CostOf returns tool's declared cost, DefaultCost if tool isn't declared
// and DefaultCost is set, or DefaultToolCost as the final fallback.
func (c Config) CostOf(tool string) int {
	if cost, ok := c.ToolCosts[tool]; ok {
		return cost
	}
	if c.DefaultCost > 0 {
		return c.DefaultCost
	}
	return DefaultToolCost
}
