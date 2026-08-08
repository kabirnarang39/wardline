package usecase

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/kabirnarang39/wardline/internal/features/policypack/domain"
)

// PackSource is the List/Get shape both Catalog and MultiCatalog share --
// cmd/wardline's CLI handlers depend on this instead of the concrete
// *Catalog type, so they work identically whether -packs-dir was given
// or not.
type PackSource interface {
	List() ([]domain.Pack, error)
	Get(name string) (domain.Pack, []byte, error)
}

// MultiCatalog merges multiple Catalogs into one pack source. sources[0]
// is treated as the authoritative, Wardline-owned catalog: a broken pack
// there fails List entirely, the same strict posture Catalog.List always
// had (a build defect in Wardline's own shipped content should be loud).
// Every later source is treated as NOT Wardline-owned (an operator's
// own -packs-dir) -- a broken pack there is skipped and logged, not
// allowed to hide every other pack, from that source or any other, from
// List.
//
// A name present in more than one source resolves to the LAST source
// that has it, in both List and Get -- an operator's own pack
// deliberately shadowing a built-in one (by reusing its name) wins over
// the built-in, never the reverse.
type MultiCatalog struct {
	sources []*Catalog
	logger  *slog.Logger
}

// NewMultiCatalog builds a MultiCatalog over sources in precedence order
// (later wins on a name collision). logger may be nil (warnings about
// skipped packs from non-first sources are then simply not logged).
func NewMultiCatalog(logger *slog.Logger, sources ...*Catalog) *MultiCatalog {
	return &MultiCatalog{sources: sources, logger: logger}
}

var _ PackSource = (*MultiCatalog)(nil)
var _ PackSource = (*Catalog)(nil)

func (m *MultiCatalog) List() ([]domain.Pack, error) {
	byName := map[string]domain.Pack{}
	var order []string
	for i, src := range m.sources {
		var packs []domain.Pack
		if i == 0 {
			var err error
			packs, err = src.List()
			if err != nil {
				return nil, err
			}
		} else {
			var errs []error
			packs, errs = src.ListLenient()
			for _, e := range errs {
				if m.logger != nil {
					m.logger.Warn("skipping unreadable policy pack", "source_index", i, "error", e)
				}
			}
		}
		for _, p := range packs {
			if _, exists := byName[p.Name]; !exists {
				order = append(order, p.Name)
			}
			byName[p.Name] = p
		}
	}
	sort.Strings(order)
	result := make([]domain.Pack, len(order))
	for i, name := range order {
		result[i] = byName[name]
	}
	return result, nil
}

func (m *MultiCatalog) Get(name string) (domain.Pack, []byte, error) {
	for i := len(m.sources) - 1; i >= 0; i-- {
		pack, policySource, err := m.sources[i].Get(name)
		if err == nil {
			return pack, policySource, nil
		}
	}
	return domain.Pack{}, nil, fmt.Errorf("unknown policy pack %q", name)
}
