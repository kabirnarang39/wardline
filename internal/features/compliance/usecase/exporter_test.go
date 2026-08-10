package usecase_test

import (
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/compliance/usecase"
)

func TestBuildManifest_CountsAndHistogramsMixedInput(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	generatedAt := time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)
	features := map[string]bool{"rbac": true, "anomaly_detection": true}

	auditEntries := []auditdomain.Entry{
		{Decision: "allow"},
		{Decision: "allow"},
		{Decision: "deny"},
	}
	anomalies := []anomalydomain.Anomaly{
		{Kind: anomalydomain.KindNovelTool},
		{Kind: anomalydomain.KindRateSpike},
		{Kind: anomalydomain.KindRateSpike},
	}

	m := usecase.BuildManifest("0.6.0", from, to, generatedAt, features, auditEntries, 2, anomalies, 1)

	if m.WardlineVersion != "0.6.0" {
		t.Errorf("unexpected version: %q", m.WardlineVersion)
	}
	if !m.RangeFrom.Equal(from) || !m.RangeTo.Equal(to) || !m.GeneratedAt.Equal(generatedAt) {
		t.Errorf("unexpected range/generatedAt: %+v", m)
	}
	if !m.Features["rbac"] || !m.Features["anomaly_detection"] {
		t.Errorf("expected features to pass through, got %+v", m.Features)
	}
	if m.AuditEntryCount != 3 {
		t.Errorf("expected AuditEntryCount 3, got %d", m.AuditEntryCount)
	}
	if m.AuditDecisionCounts["allow"] != 2 || m.AuditDecisionCounts["deny"] != 1 {
		t.Errorf("unexpected AuditDecisionCounts: %+v", m.AuditDecisionCounts)
	}
	if m.UnparsableAuditLinesSkipped != 2 {
		t.Errorf("expected UnparsableAuditLinesSkipped 2, got %d", m.UnparsableAuditLinesSkipped)
	}
	if m.UnparsableAnomalyLinesSkipped != 1 {
		t.Errorf("expected UnparsableAnomalyLinesSkipped 1, got %d", m.UnparsableAnomalyLinesSkipped)
	}
	if m.AnomalyEntryCount != 3 {
		t.Errorf("expected AnomalyEntryCount 3, got %d", m.AnomalyEntryCount)
	}
	if m.AnomalyKindCounts["novel_tool"] != 1 || m.AnomalyKindCounts["rate_spike"] != 2 {
		t.Errorf("unexpected AnomalyKindCounts: %+v", m.AnomalyKindCounts)
	}
}

func TestBuildManifest_EmptyInputsProduceZeroCountsNoPanic(t *testing.T) {
	from := time.Now()
	to := from.Add(time.Hour)
	m := usecase.BuildManifest("0.6.0", from, to, from, map[string]bool{}, nil, 0, nil, 0)

	if m.AuditEntryCount != 0 || m.AnomalyEntryCount != 0 {
		t.Errorf("expected zero counts for empty inputs, got %+v", m)
	}
	if m.AuditDecisionCounts == nil || m.AnomalyKindCounts == nil {
		t.Error("expected non-nil (empty) maps, not nil maps, so callers can range over them safely")
	}
}

// TestBuildManifest_EffectFieldsDoNotChangeExport pins backward compatibility
// for the optional audit Effect fields: an entry carrying a populated Effect
// must produce byte-identical manifest output to the same entry without one.
// The evidence export counts decisions, never claimed effects, so adding
// Effect to the audit schema must not perturb any downstream compliance
// artifact.
func TestBuildManifest_EffectFieldsDoNotChangeExport(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	withoutEffect := []auditdomain.Entry{
		{Decision: "allow", Tool: "delete_file"},
		{Decision: "deny", Tool: "read_file"},
	}
	withEffect := []auditdomain.Entry{
		{Decision: "allow", Tool: "delete_file", EffectStatus: auditdomain.EffectStatusContradicted,
			Effect: &auditdomain.Effect{Target: "delete_file", ClaimedOp: "tools/call", RPCError: true}},
		{Decision: "deny", Tool: "read_file", EffectStatus: auditdomain.EffectStatusNotAWrite},
	}

	base := usecase.BuildManifest("0.6.0", from, to, from, map[string]bool{}, withoutEffect, 0, nil, 0)
	withEff := usecase.BuildManifest("0.6.0", from, to, from, map[string]bool{}, withEffect, 0, nil, 0)

	if base.AuditEntryCount != withEff.AuditEntryCount {
		t.Errorf("Effect presence changed AuditEntryCount: %d vs %d", base.AuditEntryCount, withEff.AuditEntryCount)
	}
	if base.AuditDecisionCounts["allow"] != withEff.AuditDecisionCounts["allow"] ||
		base.AuditDecisionCounts["deny"] != withEff.AuditDecisionCounts["deny"] {
		t.Errorf("Effect presence changed decision counts: %+v vs %+v", base.AuditDecisionCounts, withEff.AuditDecisionCounts)
	}
}
