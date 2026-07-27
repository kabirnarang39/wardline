package adapter

import (
	"embed"
	"io/fs"
)

//go:embed web/dist
var embeddedAssets embed.FS

// Assets returns the embedded SPA filesystem, rooted at web/dist (so
// callers see "index.html", not "web/dist/index.html").
func Assets() fs.FS {
	sub, err := fs.Sub(embeddedAssets, "web/dist")
	if err != nil {
		// web/dist is embedded at compile time via the go:embed directive
		// above; fs.Sub only fails if that directory doesn't exist, which
		// would already be a build failure, not a runtime one.
		panic(err)
	}
	return sub
}
