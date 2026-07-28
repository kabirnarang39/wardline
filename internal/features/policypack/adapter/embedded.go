package adapter

import (
	"embed"
	"io/fs"
)

//go:embed policy-packs
var embeddedPacks embed.FS

// Packs returns the embedded pack catalog's filesystem, rooted at
// policy-packs (so callers see "<pack-name>/pack.yaml", not
// "policy-packs/<pack-name>/pack.yaml") -- the same fs.Sub pattern
// dashboard/adapter.Assets() already uses for its own embedded tree.
func Packs() fs.FS {
	sub, err := fs.Sub(embeddedPacks, "policy-packs")
	if err != nil {
		// policy-packs is embedded at compile time via the go:embed
		// directive above; fs.Sub only fails if that directory doesn't
		// exist, which would already be a build failure, not a runtime one.
		panic(err)
	}
	return sub
}
