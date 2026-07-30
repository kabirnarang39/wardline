package usecase

// tenantIdentityKey composes a tenant and identity into one map key. \x00
// can't appear in either a tenant or identity string in practice (both
// come from JWT claims / header values / SCIM UserNames), so this is a
// safe, unambiguous join -- avoids a struct key's extra allocation
// overhead on this codebase's hot path (Detector.Publish runs on every
// proxied request).
//
// Both Detector.state and BlockChecker.blocked must key exclusively
// through this one function -- never build the composite key inline at a
// call site. Two SCIM-provisioned identities from different tenants can
// plausibly share a raw identity string (two different IdPs both
// provisioning "alice"), so keying on identity alone would let one
// tenant's rate-spike or auto-block poison or lock out the other
// tenant's identically-named identity.
func tenantIdentityKey(tenantName, identity string) string {
	return tenantName + "\x00" + identity
}
