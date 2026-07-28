package domain

// Pack is one policy pack's metadata, parsed from its pack.yaml manifest.
type Pack struct {
	Name           string
	Description    string
	Backend        string
	PolicyFilename string
}
