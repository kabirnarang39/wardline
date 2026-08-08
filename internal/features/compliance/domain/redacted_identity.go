package domain

// RedactedIdentity is one provisioned identity's compliance-safe view --
// deliberately its own minimal type, not a reuse of
// credentialdomain.RegisteredIdentity, so a future field added to that
// domain type for an unrelated reason never accidentally leaks into a
// compliance bundle without a human deciding to add it here too. Never
// carries a Secret or SpiffeID -- the only two fields RegisteredIdentity
// has beyond Name/Tenant, and exactly the two a compliance auditor has
// no legitimate need to see.
type RedactedIdentity struct {
	Name   string `json:"name"`
	Tenant string `json:"tenant"`
}
