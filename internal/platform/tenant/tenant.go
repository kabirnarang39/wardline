// Package tenant holds the one constant every tenant-aware feature
// (credential, rbac, policy, budget, audit, dashboard) needs: the
// implicit tenant a caller resolves to when nothing else specifies one.
// A single shared constant, rather than each package hand-copying the
// string literal "default", so the value can't silently drift between
// packages.
package tenant

// Default is the implicit tenant for any identity/rule/binding that
// doesn't specify one — preserves every pre-this-cycle deployment's
// behavior exactly (see docs/superpowers/specs/2026-07-30-sso-scim-tenant-isolation-design.md).
const Default = "default"
