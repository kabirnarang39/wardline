package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/compliance/usecase"
)

func TestRunRetention_SkipsPurgersWithZeroOrNegativeRetentionDays(t *testing.T) {
	calls := 0
	purgers := []usecase.NamedPurger{
		{Name: "audit", RetentionDays: 0, Purge: func(ctx context.Context, cutoff time.Time) (int, error) {
			calls++
			return 0, nil
		}},
		{Name: "anomaly", RetentionDays: -1, Purge: func(ctx context.Context, cutoff time.Time) (int, error) {
			calls++
			return 0, nil
		}},
	}
	results := usecase.RunRetention(context.Background(), purgers, time.Now())
	if calls != 0 {
		t.Errorf("expected 0 Purge calls for retention_days <= 0, got %d", calls)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestRunRetention_ComputesCutoffFromRetentionDays(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	var gotCutoff time.Time
	purgers := []usecase.NamedPurger{
		{Name: "audit", RetentionDays: 30, Purge: func(ctx context.Context, cutoff time.Time) (int, error) {
			gotCutoff = cutoff
			return 5, nil
		}},
	}
	results := usecase.RunRetention(context.Background(), purgers, now)
	want := now.AddDate(0, 0, -30)
	if !gotCutoff.Equal(want) {
		t.Errorf("expected cutoff %v, got %v", want, gotCutoff)
	}
	if len(results) != 1 || results[0].Deleted != 5 || results[0].Name != "audit" {
		t.Errorf("unexpected results: %+v", results)
	}
}

func TestRunRetention_OneFailingPurgerDoesNotBlockOthers(t *testing.T) {
	auditCalled := false
	anomalyCalled := false
	purgers := []usecase.NamedPurger{
		{Name: "audit", RetentionDays: 30, Purge: func(ctx context.Context, cutoff time.Time) (int, error) {
			auditCalled = true
			return 0, errors.New("disk full")
		}},
		{Name: "anomaly", RetentionDays: 30, Purge: func(ctx context.Context, cutoff time.Time) (int, error) {
			anomalyCalled = true
			return 3, nil
		}},
	}
	results := usecase.RunRetention(context.Background(), purgers, time.Now())
	if !auditCalled || !anomalyCalled {
		t.Fatalf("expected both purgers to be called regardless of the first one's error, got auditCalled=%v anomalyCalled=%v", auditCalled, anomalyCalled)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Error("expected the audit result to carry its error")
	}
	if results[1].Err != nil || results[1].Deleted != 3 {
		t.Errorf("expected the anomaly purger to succeed independently, got %+v", results[1])
	}
}
