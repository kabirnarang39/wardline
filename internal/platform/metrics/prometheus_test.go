package metrics_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/metrics"
)

func TestNewPrometheus_HandlerServesRecordedRequest(t *testing.T) {
	r := metrics.NewPrometheus()
	r.ObserveRequest("allow", 12*time.Millisecond)
	r.ObserveRequest("deny", 3*time.Millisecond)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `wardline_proxy_requests_total{decision="allow"} 1`) {
		t.Errorf("expected allow counter in output, got:\n%s", body)
	}
	if !strings.Contains(body, `wardline_proxy_requests_total{decision="deny"} 1`) {
		t.Errorf("expected deny counter in output, got:\n%s", body)
	}
	// Go runtime collector proves the leak-detection signal (see
	// runbook.md's soak-test guidance) is actually exposed here.
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("expected go_goroutines from the Go runtime collector, got:\n%s", body)
	}
}

func TestNewPrometheus_TwoInstancesDoNotCollide(t *testing.T) {
	// Each NewPrometheus uses its own private registry -- two instances in
	// the same process (as in this very test, or a table-driven test
	// elsewhere) must not panic on duplicate registration against a
	// shared global registerer.
	a := metrics.NewPrometheus()
	b := metrics.NewPrometheus()
	a.ObserveRequest("allow", time.Millisecond)
	b.ObserveRequest("allow", time.Millisecond)
}
