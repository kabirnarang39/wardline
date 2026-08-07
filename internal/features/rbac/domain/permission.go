package domain

// Permission is a verb:resource string identifying one grantable
// capability on Wardline's admin surface.
type Permission string

const (
	// PermissionDashboardView grants read access to the dashboard
	// (status, live audit view, policy source).
	PermissionDashboardView Permission = "dashboard:view"
	// PermissionCredentialRevoke grants the ability to call
	// POST /credentials/revoke from outside loopback.
	PermissionCredentialRevoke Permission = "credential:revoke"
	// PermissionConfigEdit grants the ability to trigger a hot-reload of
	// policy, rbac, or budget configuration -- a stricter tier than
	// dashboard:view, mirroring credential:revoke's precedent for any
	// mutation with real operational/security weight.
	PermissionConfigEdit Permission = "config:edit"
)
