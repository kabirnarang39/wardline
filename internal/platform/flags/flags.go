package flags

// Provider answers whether a named feature flag is enabled. v0.1 shipped no
// flagged features (proxy/policy/audit are always on); budget enforcement
// is now the first real, working example of a flagged feature plugging
// into this interface, with more (approval workflows, Cedar backend, etc.)
// expected to follow the same pattern.
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
