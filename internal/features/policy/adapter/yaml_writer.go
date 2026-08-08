package adapter

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

// MarshalYAML renders rules/def into the same policy.yaml-shaped bytes
// ParseYAML/LoadFile read back -- exported so a caller (WriteFile below,
// or a test) can inspect exactly what will be persisted before it is.
func MarshalYAML(rules []domain.Rule, def domain.Effect) ([]byte, error) {
	out := make([]ruleYAML, len(rules))
	for i, r := range rules {
		out[i] = ruleYAML{Identity: r.Identity, Tool: r.Tool, Tenant: r.Tenant, Effect: string(r.Effect), Method: r.Method}
	}
	data, err := yaml.Marshal(policyYAML{Rules: out, Default: string(def)})
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return data, nil
}

// WriteFile validates rules/def, then atomically overwrites the policy
// file at path with them -- unlike policygen/adapter.WriteFile (which
// O_EXCL-refuses to touch an existing file, since it writes a brand-new
// generated file an operator hasn't reviewed yet), this is the dashboard
// editor's save path: overwriting the operator's own already-reviewed,
// already-live policy file is the whole point.
//
// "Atomically" means write-to-temp-then-rename (same directory as path,
// so the rename is same-filesystem and POSIX-atomic): a crash or power
// loss mid-write leaves either the old file or the new one intact, never
// a half-written policy file a subsequent process restart would load.
// Validation happens BEFORE any write via ParseYAML on the exact bytes
// about to be persisted -- this file must never contain content that
// wouldn't itself pass a reload, so a caller doesn't need a second
// round-trip through the live reload path just to find out a save was
// bad; reload after a successful WriteFile call is expected to succeed.
func WriteFile(path string, rules []domain.Rule, def domain.Effect) error {
	data, err := MarshalYAML(rules, def)
	if err != nil {
		return err
	}
	if _, err := ParseYAML(data); err != nil {
		return fmt.Errorf("refusing to write invalid policy: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policy-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Any early return below must clean up the temp file -- only the
	// final, successful os.Rename is allowed to let it survive (renamed
	// to path, no longer at tmpPath).
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
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
