package usecase

import (
	"fmt"
	"io/fs"
	"path"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/policypack/domain"
)

type packYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Backend     string `yaml:"backend"`
	PolicyFile  string `yaml:"policy_file"`
}

// Catalog loads policy packs from fsys, where each pack is a top-level
// directory containing a pack.yaml manifest and the policy file it names.
// The directory name must equal the pack's own "name" field -- Get looks
// up a pack by treating the requested name as the directory to open.
type Catalog struct {
	fsys fs.FS
}

func NewCatalog(fsys fs.FS) *Catalog {
	return &Catalog{fsys: fsys}
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

func (c *Catalog) loadPack(dirName string) (domain.Pack, []byte, error) {
	manifestPath := path.Join(dirName, "pack.yaml")
	data, err := fs.ReadFile(c.fsys, manifestPath)
	if err != nil {
		return domain.Pack{}, nil, fmt.Errorf("unknown policy pack %q", dirName)
	}
	var raw packYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return domain.Pack{}, nil, fmt.Errorf("parse pack manifest %s: %w", manifestPath, err)
	}
	policyPath := path.Join(dirName, raw.PolicyFile)
	policySource, err := fs.ReadFile(c.fsys, policyPath)
	if err != nil {
		return domain.Pack{}, nil, fmt.Errorf("read policy file for pack %q: %w", raw.Name, err)
	}
	return domain.Pack{
		Name:           raw.Name,
		Description:    raw.Description,
		Backend:        raw.Backend,
		PolicyFilename: raw.PolicyFile,
	}, policySource, nil
}
