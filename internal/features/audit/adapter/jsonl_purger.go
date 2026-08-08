package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// JSONLPurger implements audit/domain.Purger by rewriting a JSONLWriter-
// produced file, keeping only lines whose timestamp is >= cutoff. Uses
// the same write-to-temp-file-in-same-directory-then-rename atomic
// pattern policyadapter.WriteFile established: a crash mid-rewrite must
// never leave a corrupted or half-purged audit trail -- the integrity
// guarantee compliance evidence depends on must survive the retention
// job that's supposed to be pruning it.
//
// A line that fails to parse (or whose timestamp fails to parse) is
// always KEPT, never dropped -- retention must never destroy data it
// can't confidently place in time; an unparsable line is exactly the
// kind of anomaly an operator investigating gaps in the audit trail
// needs to still find on disk, not have silently vanish during routine
// maintenance.
type JSONLPurger struct {
	path string
}

func NewJSONLPurger(path string) *JSONLPurger {
	return &JSONLPurger{path: path}
}

var _ domain.Purger = (*JSONLPurger)(nil)

func (p *JSONLPurger) Purge(ctx context.Context, cutoff time.Time) (int, error) {
	f, err := os.Open(p.path)
	if err != nil {
		return 0, fmt.Errorf("open audit file %s: %w", p.path, err)
	}

	var kept bytes.Buffer
	deleted := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return 0, err
		}
		line := scanner.Bytes()
		var raw entryJSON
		if err := json.Unmarshal(line, &raw); err != nil {
			kept.Write(line)
			kept.WriteByte('\n')
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05Z07:00", raw.Timestamp)
		if err != nil || !ts.Before(cutoff) {
			kept.Write(line)
			kept.WriteByte('\n')
			continue
		}
		deleted++
	}
	scanErr := scanner.Err()
	_ = f.Close()
	if scanErr != nil {
		return 0, fmt.Errorf("scan audit file %s: %w", p.path, scanErr)
	}

	if deleted == 0 {
		return 0, nil
	}

	dir := filepath.Dir(p.path)
	tmp, err := os.CreateTemp(dir, ".audit-*.jsonl.tmp")
	if err != nil {
		return 0, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return 0, fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(kept.Bytes()); err != nil {
		_ = tmp.Close()
		return 0, fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, p.path); err != nil {
		return 0, fmt.Errorf("rename %s to %s: %w", tmpPath, p.path, err)
	}
	cleanup = false
	return deleted, nil
}
