package flags

// Provider answers whether a named feature flag is enabled. v0.1 ships no
// flagged features (proxy/policy/audit are always on) — this interface
// exists so v0.5+ features (approval workflows, Cedar backend, etc.) have
// a place to plug into without a rewrite.
type Provider interface {
	Enabled(name string) bool
}

// StaticProvider reads flags from a fixed map, loaded from the operator's
// config file. A missing key defaults to false (disabled).
type StaticProvider struct {
	flags map[string]bool
}

func NewStaticProvider(flags map[string]bool) *StaticProvider {
	return &StaticProvider{flags: flags}
}

func (p *StaticProvider) Enabled(name string) bool {
	return p.flags[name]
}
