package domain

// RegisteredIdentity is one entry from credentials.yaml: an identity name
// bound to either a preshared registration secret (presharedsecret
// bootstrap source) or a SPIFFE ID (mtls bootstrap source), and the
// tenant it belongs to (optional -- an omitted tenant resolves to
// tenant.Default at load time in presharedsecret.LoadBootstrapper /
// mtls.LoadMTLSBootstrapper, not here, since domain packages don't
// import platform/tenant to avoid a domain->platform dependency for a
// single string default).
//
// Secret and SpiffeID are mutually exclusive in practice -- an operator
// runs one bootstrap source per Wardline instance, so each entry only
// ever populates the field its chosen source reads; the loader for the
// other source simply never looks at the unused field.
type RegisteredIdentity struct {
	Name     string
	Secret   string
	Tenant   string
	SpiffeID string `yaml:"spiffe_id"`
}
