package usecase_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}

func embeddedLikeFS() fstest.MapFS {
	return fstest.MapFS{
		"built-in/pack.yaml": &fstest.MapFile{Data: []byte(`
name: built-in
description: "ships with wardline"
backend: yaml
policy_file: policy.yaml
`)},
		"built-in/policy.yaml": &fstest.MapFile{Data: []byte("default: deny\n")},
	}
}

func TestMultiCatalog_ListMergesSources(t *testing.T) {
	external := fstest.MapFS{
		"custom/pack.yaml": &fstest.MapFile{Data: []byte(`
name: custom
description: "operator-owned"
backend: yaml
policy_file: policy.yaml
`)},
		"custom/policy.yaml": &fstest.MapFile{Data: []byte("default: allow\n")},
	}
	mc := usecase.NewMultiCatalog(discardLogger(),
		usecase.NewCatalog(embeddedLikeFS(), fakeDecoder{}),
		usecase.NewCatalog(external, fakeDecoder{}),
	)

	packs, err := mc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(packs) != 2 {
		t.Fatalf("expected 2 packs, got %d: %+v", len(packs), packs)
	}
	if packs[0].Name != "built-in" || packs[1].Name != "custom" {
		t.Errorf("expected packs sorted by name [built-in, custom], got [%s, %s]", packs[0].Name, packs[1].Name)
	}
}

func TestMultiCatalog_NameCollision_LaterSourceWins(t *testing.T) {
	embedded := embeddedLikeFS()
	override := fstest.MapFS{
		"built-in/pack.yaml": &fstest.MapFile{Data: []byte(`
name: built-in
description: "operator's own override of the built-in name"
backend: yaml
policy_file: policy.yaml
`)},
		"built-in/policy.yaml": &fstest.MapFile{Data: []byte("default: allow\n")},
	}
	mc := usecase.NewMultiCatalog(discardLogger(),
		usecase.NewCatalog(embedded, fakeDecoder{}),
		usecase.NewCatalog(override, fakeDecoder{}),
	)

	packs, err := mc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected exactly 1 pack (collision merged, not duplicated), got %d: %+v", len(packs), packs)
	}
	if packs[0].Description != "operator's own override of the built-in name" {
		t.Errorf("expected the later (external) source to win on name collision, got %+v", packs[0])
	}

	_, policySource, err := mc.Get("built-in")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(policySource) != "default: allow\n" {
		t.Errorf("expected Get to also resolve to the later source's content, got %q", policySource)
	}
}

func TestMultiCatalog_BrokenExternalPack_DoesNotHideOthers(t *testing.T) {
	external := fstest.MapFS{
		"broken/pack.yaml": &fstest.MapFile{Data: []byte("not: [valid, yaml, manifest")},
		"good/pack.yaml":   &fstest.MapFile{Data: []byte("name: good\ndescription: fine\nbackend: yaml\npolicy_file: policy.yaml\n")},
		"good/policy.yaml": &fstest.MapFile{Data: []byte("default: deny\n")},
	}
	mc := usecase.NewMultiCatalog(discardLogger(),
		usecase.NewCatalog(embeddedLikeFS(), fakeDecoder{}),
		usecase.NewCatalog(external, fakeDecoder{}),
	)

	packs, err := mc.List()
	if err != nil {
		t.Fatalf("expected List to succeed despite one broken external pack, got error: %v", err)
	}
	var names []string
	for _, p := range packs {
		names = append(names, p.Name)
	}
	foundBuiltIn, foundGood := false, false
	for _, n := range names {
		if n == "built-in" {
			foundBuiltIn = true
		}
		if n == "good" {
			foundGood = true
		}
	}
	if !foundBuiltIn || !foundGood {
		t.Errorf("expected both built-in and good to survive a broken sibling pack, got %v", names)
	}
}

func TestMultiCatalog_BrokenFirstSource_FailsListEntirely(t *testing.T) {
	mc := usecase.NewMultiCatalog(discardLogger(), usecase.NewCatalog(errorFS{}, fakeDecoder{}))
	if _, err := mc.List(); err == nil {
		t.Fatal("expected List to fail hard when the first (authoritative) source errors")
	}
}

// errorFS is an fs.FS that fails every Open call.
type errorFS struct{}

func (errorFS) Open(name string) (fs.File, error) {
	return nil, fmt.Errorf("errorFS: forced failure opening %q", name)
}

func TestMultiCatalog_UnknownName_ReturnsClearError(t *testing.T) {
	mc := usecase.NewMultiCatalog(discardLogger(), usecase.NewCatalog(embeddedLikeFS(), fakeDecoder{}))
	_, _, err := mc.Get("does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown pack name")
	}
}

func TestMultiCatalog_SingleSourceBehavesLikePlainCatalog(t *testing.T) {
	mc := usecase.NewMultiCatalog(discardLogger(), usecase.NewCatalog(embeddedLikeFS(), fakeDecoder{}))
	packs, err := mc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(packs) != 1 || packs[0].Name != "built-in" {
		t.Errorf("expected single-source behavior identical to a plain Catalog, got %+v", packs)
	}
}
