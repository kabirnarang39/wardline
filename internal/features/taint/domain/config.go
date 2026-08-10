package domain

// TaintConfig is the operator-supplied taint-tracking configuration. All
// fields are optional; the engine applies defaults for the numeric ones.
type TaintConfig struct {
	// UntrustedSources are tool names whose invocation taints the calling
	// (tenant, identity, session) — e.g. a web-fetch tool that pulls
	// attacker-controllable content into the agent's context.
	UntrustedSources []string

	// DeclassifySources are tool names that explicitly clear taint — an
	// operator-audited "the agent sanitized / a human approved" event.
	DeclassifySources []string

	// TTLSeconds is how long a taint label stays live before lazy expiry.
	// A read past SetAt+TTL is treated as untainted. <=0 uses DefaultTTLSeconds.
	TTLSeconds int

	// SessionWindowSeconds is the sliding-window width for the fallback
	// session id used when no session header is present. <=0 uses
	// DefaultSessionWindowSeconds.
	SessionWindowSeconds int

	// SessionHeader is the request header carrying an explicit session id.
	// Empty uses DefaultSessionHeader.
	SessionHeader string
}

// Defaults for the numeric/string TaintConfig fields.
const (
	DefaultTTLSeconds           = 300
	DefaultSessionWindowSeconds = 300
	DefaultSessionHeader        = "X-Wardline-Session"
)

// TTL returns the configured TTL in seconds, or the default when unset.
func (c TaintConfig) TTL() int {
	if c.TTLSeconds <= 0 {
		return DefaultTTLSeconds
	}
	return c.TTLSeconds
}

// Window returns the configured session-window width in seconds, or the
// default when unset.
func (c TaintConfig) Window() int {
	if c.SessionWindowSeconds <= 0 {
		return DefaultSessionWindowSeconds
	}
	return c.SessionWindowSeconds
}

// Header returns the configured session header name, or the default.
func (c TaintConfig) Header() string {
	if c.SessionHeader == "" {
		return DefaultSessionHeader
	}
	return c.SessionHeader
}
