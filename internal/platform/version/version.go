// Package version holds Wardline's build version, surfaced on the
// dashboard's Status view. Bumped by hand at release time until a real
// release-automation step (ldflags injection, goreleaser, etc.) exists —
// no such step exists yet in this repo.
package version

const Version = "2.0.0"
