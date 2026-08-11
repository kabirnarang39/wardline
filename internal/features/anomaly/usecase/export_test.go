package usecase

import "time"

// TenantWindowStartForTest exposes tenantState's windowStart for one
// tenant, for external (usecase_test package) tests only -- an exported
// name defined only in a _test.go file never appears in production
// builds, the standard Go convention for reaching unexported state from
// black-box tests without widening the real API.
func TenantWindowStartForTest(d *Detector, tenantName string) time.Time {
	if d.tenantState == nil {
		return time.Time{}
	}
	ts, ok := d.tenantState[tenantName]
	if !ok {
		return time.Time{}
	}
	return ts.windowStart
}
