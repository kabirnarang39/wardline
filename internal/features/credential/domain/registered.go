package domain

// RegisteredIdentity is one entry from credentials.yaml: an identity name
// bound to a preshared registration secret, and the tenant it belongs
// to (optional -- an omitted tenant resolves to tenant.Default at load
// time in presharedsecret.LoadBootstrapper, not here, since domain
// packages don't import platform/tenant to avoid a domain->platform
// dependency for a single string default).
type RegisteredIdentity struct {
	Name   string
	Secret string
	Tenant string
}
