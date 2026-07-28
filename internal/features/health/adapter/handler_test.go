package adapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/health/adapter"
)

func TestHandler_Healthz_AlwaysReturns200(t *testing.T) {
	h := adapter.NewHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", w.Code)
	}
}

func TestHandler_Healthz_StillReturns200WhileDraining(t *testing.T) {
	h := adapter.NewHandler(nil)
	h.SetDraining(true)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected /healthz to stay 200 during a drain (liveness must not depend on readiness), got %d", w.Code)
	}
}

func TestHandler_Readyz_Returns200BeforeDraining(t *testing.T) {
	h := adapter.NewHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /readyz before SetDraining, got %d", w.Code)
	}
}

func TestHandler_Readyz_Returns503AfterSetDrainingTrue(t *testing.T) {
	h := adapter.NewHandler(nil)
	h.SetDraining(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from /readyz after SetDraining(true), got %d", w.Code)
	}
}

func TestHandler_Readyz_ReturnsToReadyIfSetDrainingFalse(t *testing.T) {
	h := adapter.NewHandler(nil)
	h.SetDraining(true)
	h.SetDraining(false)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /readyz after SetDraining(false), got %d", w.Code)
	}
}

func TestHandler_Readyz_PingerFailureReturns503(t *testing.T) {
	h := adapter.NewHandler(func(ctx context.Context) error {
		return errors.New("connection refused")
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from /readyz when the pinger fails, got %d", w.Code)
	}
}

func TestHandler_Readyz_PingerSuccessReturns200(t *testing.T) {
	h := adapter.NewHandler(func(ctx context.Context) error {
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /readyz when the pinger succeeds, got %d", w.Code)
	}
}

func TestHandler_UnknownPathReturns404(t *testing.T) {
	h := adapter.NewHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/not-a-real-path", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unmatched path, got %d", w.Code)
	}
}
