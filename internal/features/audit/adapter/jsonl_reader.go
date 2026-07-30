package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// JSONLReader implements audit/domain.Reader by scanning a JSONL file
// written by JSONLWriter (reuses entryJSON, this package's existing
// wire-format type, so reader and writer can never drift apart). Built
// for the single-invocation export-evidence CLI command, not a
// concurrent/live query path -- not safe for concurrent Query calls
// against the same *JSONLReader (SkippedLines is reset per call).
type JSONLReader struct {
	path string

	// SkippedLines is the number of lines the most recent Query call
	// could not parse as valid JSON or whose timestamp couldn't be
	// parsed -- most plausibly a truncated last line from a process
	// killed mid-write. Reset at the start of every Query call; read it
	// only after Query returns.
	SkippedLines int
}

func NewJSONLReader(path string) *JSONLReader {
	return &JSONLReader{path: path}
}

var _ domain.Reader = (*JSONLReader)(nil)

func (r *JSONLReader) Query(ctx context.Context, from, to time.Time) ([]domain.Entry, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return nil, fmt.Errorf("open audit file %s: %w", r.path, err)
	}
	defer func() { _ = f.Close() }()

	r.SkippedLines = 0
	var entries []domain.Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var raw entryJSON
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			r.SkippedLines++
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05Z07:00", raw.Timestamp)
		if err != nil {
			r.SkippedLines++
			continue
		}
		if ts.Before(from) || !ts.Before(to) {
			continue
		}
		entryTenant := raw.Tenant
		if entryTenant == "" {
			// A pre-Task-19 line has no "tenant" key at all -- default it
			// rather than let a scoping check see an empty string, which
			// would silently match nothing (or everything, depending on
			// the check) instead of the pre-existing single-tenant
			// deployment's real tenant.
			entryTenant = tenant.Default
		}
		entries = append(entries, domain.Entry{
			Timestamp: ts,
			Identity:  raw.Identity,
			Tenant:    entryTenant,
			Tool:      raw.Tool,
			Decision:  raw.Decision,
			LatencyMS: raw.LatencyMS,
			Reason:    raw.Reason,
			TraceID:   raw.TraceID,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan audit file %s: %w", r.path, err)
	}
	return entries, nil
}
