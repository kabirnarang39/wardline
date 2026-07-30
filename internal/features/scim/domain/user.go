package domain

// User is a SCIM-provisioned identity, mapped from a SCIM 2.0 User
// resource's userName and active attributes -- this cycle intentionally
// tracks only what RBAC/credential need, not the full SCIM User schema.
type User struct {
	ID       string
	UserName string
	Active   bool
}
