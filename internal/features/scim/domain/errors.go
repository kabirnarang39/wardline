package domain

import "errors"

// ErrNotFound is returned when a SCIM resource ID doesn't exist —
// mapped to HTTP 404 with an RFC 7644 §3.12-shaped body at the adapter.
var ErrNotFound = errors.New("scim: resource not found")

// ErrConflict is returned when a Create would duplicate an existing
// resource's unique key (userName / displayName) — mapped to HTTP 409.
var ErrConflict = errors.New("scim: resource already exists")
