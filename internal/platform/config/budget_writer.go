package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// WriteBudgetSection validates and atomically overwrites ONLY the
// top-level "budget:" key in the config file at path -- every other
// key (listen, upstream, policy_file, features, anomaly, rbac, ...),
// including their comments and relative order, survives byte-for-byte
// untouched. This is the dashboard Budget editor's save path: unlike
// policy (its own dedicated file, see policyadapter.WriteFile), budget
// config lives inside the shared main config file (see
// newBudgetReloadFn in cmd/wardline/main.go, which re-reads the WHOLE
// file on reload), so a naive "marshal a fresh Config and overwrite"
// would silently discard every unrelated setting an operator has -- a
// surgical, node-level edit is not optional here.
//
// "Atomically" means write-to-temp-then-rename in path's own directory
// (same filesystem, POSIX-atomic rename): a crash or power loss
// mid-write leaves either the old file or the new one intact, never a
// half-written config file a subsequent process restart would load.
// Validation happens on the exact bytes about to be persisted, via the
// SAME ParseBytes/validate() a real Load applies at startup -- a bad
// write (e.g. requests_per_window <= 0) is rejected before it ever
// reaches disk, never a second round-trip through the live reload path
// just to find out a save was bad.
func WriteBudgetSection(path string, budget BudgetConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config file %s is not a YAML mapping", path)
	}
	doc := root.Content[0]

	// doc.Content alternates [key1, value1, key2, value2, ...] -- find
	// the existing "budget" value node to replace in place (preserving
	// its position and any comments attached to the key), or append a
	// new key/value pair if the file had no budget: section yet.
	var valueNode *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "budget" {
			valueNode = doc.Content[i+1]
			break
		}
	}
	if valueNode == nil {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "budget"}
		valueNode = &yaml.Node{}
		doc.Content = append(doc.Content, keyNode, valueNode)
	}
	// Encode replaces valueNode's own Kind/Content with budget's, in
	// place -- everything else in doc.Content is untouched by identity,
	// not just by value.
	if err := valueNode.Encode(budget); err != nil {
		return fmt.Errorf("encode budget section: %w", err)
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if _, err := ParseBytes(out); err != nil {
		return fmt.Errorf("refusing to write invalid config: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	cleanup = false
	return nil
}
