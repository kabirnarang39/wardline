package usecase_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/audit/usecase"
)

type fakeWriter struct {
	entries []domain.Entry
	failWith error
}

func (f *fakeWriter) Write(e domain.Entry) error {
	if f.failWith != nil {
		return f.failWith
	}
	f.entries = append(f.entries, e)
	return nil
}

func TestRecorder_Record_Success(t *testing.T) {
	w := &fakeWriter{}
	r := usecase.NewRecorder(w, nil)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.Record("agent-abc123", "read_file", "allow", "matched rule", "", 42*time.Millisecond, now)

	if len(w.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(w.entries))
	}
	got := w.entries[0]
	if got.Identity != "agent-abc123" || got.Tool != "read_file" || got.Decision != "allow" {
		t.Errorf("unexpected entry: %+v", got)
	}
	if got.Reason != "matched rule" {
		t.Errorf("expected reason %q, got %q", "matched rule", got.Reason)
	}
	if got.LatencyMS != 42 {
		t.Errorf("expected latency 42ms, got %d", got.LatencyMS)
	}
	if !got.Timestamp.Equal(now) {
		t.Errorf("expected timestamp %v, got %v", now, got.Timestamp)
	}
}

func TestRecorder_Record_WriteFailureCallsOnError(t *testing.T) {
	w := &fakeWriter{failWith: errors.New("disk full")}
	var captured error
	r := usecase.NewRecorder(w, func(err error) { captured = err })

	r.Record("agent-abc123", "read_file", "allow", "", "", 0, time.Now())

	if captured == nil {
		t.Fatal("expected onError to be called")
	}
}

func TestRecorder_Record_IncludesTraceID(t *testing.T) {
	w := &fakeWriter{}
	r := usecase.NewRecorder(w, nil)

	r.Record("agent-abc123", "read_file", "allow", "matched rule", "4bf92f3577b34da6a3ce929d0e0e4736", time.Millisecond, time.Now())

	if len(w.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(w.entries))
	}
	if w.entries[0].TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected TraceID to be forwarded, got %q", w.entries[0].TraceID)
	}
}
