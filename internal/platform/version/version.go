// Package version holds Wardline's build version, surfaced on the
// dashboard's Status view. Overridable at build time via
// -ldflags "-X .../version.Version=..."; goreleaser sets it from the git
// tag (see .goreleaser.yaml). The default applies to plain `go build`.
package version

// Version is a var (not a const) so release tooling can inject the tag.
var Version = "2.0.0"
