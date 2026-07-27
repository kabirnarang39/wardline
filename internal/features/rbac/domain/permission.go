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
)
