package usecase

import "github.com/kabirnarang39/wardline/internal/platform/tenant"

// tenantIdentityKey composes a tenant and identity into one map key --
// a thin local alias for the shared tenant.Key join (promoted there so
// budget's identity bucket can share the exact same implementation
// instead of a second hand-copied one).
//
// Both Detector.state and BlockChecker.blocked must key exclusively
// through this one function -- never build the composite key inline at a
// call site. Two SCIM-provisioned identities from different tenants can
// plausibly share a raw identity string (two different IdPs both
// provisioning "alice"), so keying on identity alone would let one
// tenant's rate-spike or auto-block poison or lock out the other
// tenant's identically-named identity.
func tenantIdentityKey(tenantName, identity string) string {
	return tenant.Key(tenantName, identity)
}
