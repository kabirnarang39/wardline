package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	"github.com/stretchr/testify/assert"
)

// fakeLister is a minimal domain.Lister implementation -- this test exists
// to pin the interface's shape (a compile-time check that Lister is
// satisfiable with exactly this method) plus Entry's zero value, not to
// exercise any real logic (there is none in this file).
type fakeLister struct{ entries []domain.Entry }

func (f fakeLister) ListNearCeiling(limit int) []domain.Entry {
	if limit < len(f.entries) {
		return f.entries[:limit]
	}
	return f.entries
}

func TestLister_Interface_IsSatisfiable(t *testing.T) {
	var l domain.Lister = fakeLister{entries: []domain.Entry{{Key: "3:acmealice", Count: 42}}}
	got := l.ListNearCeiling(10)
	assert.Equal(t, []domain.Entry{{Key: "3:acmealice", Count: 42}}, got)
}

func TestEntry_ZeroValueIsUnset(t *testing.T) {
	var e domain.Entry
	assert.Equal(t, "", e.Key)
	assert.Equal(t, 0, e.Count)
}
