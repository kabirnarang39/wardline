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
