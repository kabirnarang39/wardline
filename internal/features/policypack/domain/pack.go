package domain

// Pack is one policy pack's metadata, parsed from its pack.yaml manifest.
type Pack struct {
	Name           string
	Description    string
	Backend        string
	PolicyFilename string

	// Version is metadata only -- no upgrade/changelog tooling reads it
	// today. "" from a pack.yaml predating this field defaults to "1" at
	// load time (see catalog.go), so every pack shipped before this
	// field existed keeps working with zero manifest edits required.
	Version string
}

// Manifest is a pack.yaml's fields, decoded but not yet defaulted --
// ManifestDecoder's return shape. Catalog (usecase) applies the
// absent-version-defaults-to-"1" rule on top of this; the decoder itself
// only decodes.
type Manifest struct {
	Name        string
	Description string
	Backend     string
	PolicyFile  string
	Version     string
}

// ManifestDecoder parses a pack.yaml manifest's raw bytes into a Manifest.
// A domain interface -- per CLAUDE.md's dependency rule, usecase depends on
// this instead of importing a YAML library directly; the concrete decoder
// lives in adapter.
type ManifestDecoder interface {
	Decode(data []byte) (Manifest, error)
}
