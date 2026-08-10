package domain

// Config is the operator-supplied approval configuration.
type Config struct {
	// GrantTTLSeconds is how long an approval grant remains valid
	// before lazy expiry. A read past IssuedAt+GrantTTL is treated as
	// expired. <=0 uses DefaultGrantTTLSeconds.
	GrantTTLSeconds int
}

// Defaults for the numeric Config fields.
const (
	DefaultGrantTTLSeconds = 300
)

// GrantTTL returns the configured grant TTL in seconds, or the default when unset.
func (c Config) GrantTTL() int {
	if c.GrantTTLSeconds <= 0 {
		return DefaultGrantTTLSeconds
	}
	return c.GrantTTLSeconds
}
