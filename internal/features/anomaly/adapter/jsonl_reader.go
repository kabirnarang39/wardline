package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// JSONLReader reads anomaly records written by this package's
// JSONLWriter (reuses anomalyJSON, this package's existing wire-format
// type). Structurally identical scan-and-filter shape to
// audit/adapter.JSONLReader, kept as its own type since anomalies are a
// distinct schema from audit entries (see anomaly/adapter.JSONLWriter's
// own doc comment for why the two streams are never conflated). Not for
// concurrent use -- single-invocation CLI export only.
type JSONLReader struct {
	path string

	// SkippedLines mirrors audit/adapter.JSONLReader's field of the same
	// name -- see there for the full rationale.
	SkippedLines int
}

func NewJSONLReader(path string) *JSONLReader {
	return &JSONLReader{path: path}
}

func (r *JSONLReader) Query(ctx context.Context, from, to time.Time) ([]domain.Anomaly, error) {
	// Same fix as audit/adapter.JSONLReader.Query, same root cause: every
	// line's own timestamp round-trips at whole-second precision (see
	// JSONLWriter), but from/to are full-precision time.Time values --
	// without truncating both here, an anomaly recorded in the same
	// wall-clock second as a scheduled-export tick's own time.Now() could
	// be silently dropped from every export.
	from = from.Truncate(time.Second)
	to = to.Truncate(time.Second)

	f, err := os.Open(r.path)
	if err != nil {
		return nil, fmt.Errorf("open anomaly file %s: %w", r.path, err)
	}
	defer func() { _ = f.Close() }()

	r.SkippedLines = 0
	var anomalies []domain.Anomaly
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var raw anomalyJSON
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
		anomalies = append(anomalies, domain.Anomaly{
			Timestamp: ts,
			Identity:  raw.Identity,
			Kind:      domain.Kind(raw.Kind),
			Detail:    raw.Detail,
			Entry:     auditdomain.Entry{Tool: raw.Tool, Decision: raw.Decision},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan anomaly file %s: %w", r.path, err)
	}
	return anomalies, nil
}
