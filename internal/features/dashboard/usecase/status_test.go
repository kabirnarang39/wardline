package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/dashboard/usecase"
)

func TestStatusProvider_Status(t *testing.T) {
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fakeNow := func() time.Time { return started.Add(90 * time.Second) }

	sp := usecase.NewStatusProvider(
		"0.5.0-dev",
		":8080",
		"http://localhost:9000",
		map[string]bool{"web_ui": true, "budget_enforcement": false},
		started,
		fakeNow,
	)

	got := sp.Status()

	if got.Version != "0.5.0-dev" {
		t.Errorf("Version = %q, want %q", got.Version, "0.5.0-dev")
	}
	if got.UptimeSeconds != 90 {
		t.Errorf("UptimeSeconds = %d, want 90", got.UptimeSeconds)
	}
	if got.Listen != ":8080" || got.Upstream != "http://localhost:9000" {
		t.Errorf("Listen/Upstream = %q/%q, want :8080/http://localhost:9000", got.Listen, got.Upstream)
	}
	if !got.Features["web_ui"] || got.Features["budget_enforcement"] {
		t.Errorf("Features = %+v, want web_ui=true, budget_enforcement=false", got.Features)
	}
}
