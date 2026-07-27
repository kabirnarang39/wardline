package domain

// RegisteredIdentity is one entry from credentials.yaml: an identity name
// bound to a preshared registration secret.
type RegisteredIdentity struct {
	Name   string
	Secret string
}
