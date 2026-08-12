package adapter_test

import (
	"io"
	"strings"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
)

// TestAssets_AppJS_SupportsHashRouting is a smoke test against the real
// embedded app.js, not a fake fs.FS -- the SPA's own view-switching
// logic can't be exercised by a Go test (no JS runtime here), but a
// silent regression on this specific fix (a bookmarked or shared
// #/<view> link, or the browser back/forward buttons, landing back on
// whatever view happened to be showing instead of the one the URL
// names -- confirmed via a real browser, see the commit this test
// ships with) is cheap to guard against by asserting the fix's own
// code is still present.
func TestAssets_AppJS_SupportsHashRouting(t *testing.T) {
	f, err := adapter.Assets().Open("app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	for _, want := range []string{"viewFromHash", "popstate", "history.pushState"} {
		if !strings.Contains(src, want) {
			t.Errorf("expected app.js to contain %q (hash-based deep-linking support)", want)
		}
	}
}
