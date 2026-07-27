package domain

// Role is a named set of permissions.
type Role struct {
	Name        string
	Permissions []Permission
}
