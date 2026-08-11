package usecase

import (
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/kabirnarang39/wardline/internal/features/policypack/domain"
)

// defaultPackVersion is what an absent pack.yaml "version:" key means --
// every pack written before that field existed.
const defaultPackVersion = "1"

// Catalog loads policy packs from fsys, where each pack is a top-level
// directory containing a pack.yaml manifest and the policy file it names.
// The directory name must equal the pack's own "name" field -- Get looks
// up a pack by treating the requested name as the directory to open.
type Catalog struct {
	fsys    fs.FS
	decoder domain.ManifestDecoder
}

// NewCatalog builds a Catalog over fsys, decoding each pack.yaml manifest
// with decoder -- injected rather than hardcoded so this package never
// imports a concrete parsing library itself (see domain.ManifestDecoder).
// Production callers pass adapter.YAMLManifestDecoder{}.
func NewCatalog(fsys fs.FS, decoder domain.ManifestDecoder) *Catalog {
	return &Catalog{fsys: fsys, decoder: decoder}
}

// List returns every pack found in fsys, sorted by name.
//
// One unreadable pack fails the whole listing rather than being skipped
// with a warning. That's deliberate: fsys is the fixed catalog Wardline
// itself owns, ships inside its own binary, and covers with a test that
// loads every pack through the real policy loader -- a broken pack there
// is a Wardline build defect that should be loud, not a third-party pack
// that shouldn't be allowed to take down `list` for everyone else. If
// this ever loads packs Wardline doesn't own (a live registry, an
// operator-supplied directory), skip-and-warn becomes the right
// behaviour instead.
func (c *Catalog) List() ([]domain.Pack, error) {
	entries, err := fs.ReadDir(c.fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read pack catalog: %w", err)
	}
	var packs []domain.Pack
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pack, _, err := c.loadPack(e.Name())
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	return packs, nil
}

// Get returns the named pack's metadata and its policy file's raw source.
func (c *Catalog) Get(name string) (domain.Pack, []byte, error) {
	return c.loadPack(name)
}

// ListLenient is List's fault-tolerant sibling: a pack that fails to
// load is skipped and its error collected, rather than aborting the
// whole listing. Not used for the embedded catalog (List's strict
// all-or-nothing behavior is what a build-time test catches a Wardline
// packaging defect with) -- exists for MultiCatalog to use against a
// non-Wardline-owned source (an operator's own -packs-dir), where one
// broken pack must not hide every other pack in that directory.
func (c *Catalog) ListLenient() (packs []domain.Pack, errs []error) {
	entries, err := fs.ReadDir(c.fsys, ".")
	if err != nil {
		return nil, []error{fmt.Errorf("read pack catalog: %w", err)}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pack, _, err := c.loadPack(e.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		packs = append(packs, pack)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	return packs, errs
}

func (c *Catalog) loadPack(dirName string) (domain.Pack, []byte, error) {
	manifestPath := path.Join(dirName, "pack.yaml")
	data, err := fs.ReadFile(c.fsys, manifestPath)
	if err != nil {
		return domain.Pack{}, nil, fmt.Errorf("unknown policy pack %q", dirName)
	}
	raw, err := c.decoder.Decode(data)
	if err != nil {
		return domain.Pack{}, nil, fmt.Errorf("parse pack manifest %s: %w", manifestPath, err)
	}
	policyPath := path.Join(dirName, raw.PolicyFile)
	policySource, err := fs.ReadFile(c.fsys, policyPath)
	if err != nil {
		return domain.Pack{}, nil, fmt.Errorf("read policy file for pack %q: %w", raw.Name, err)
	}
	version := raw.Version
	if version == "" {
		version = defaultPackVersion
	}
	return domain.Pack{
		Name:           raw.Name,
		Description:    raw.Description,
		Backend:        raw.Backend,
		PolicyFilename: raw.PolicyFile,
		Version:        version,
	}, policySource, nil
}
