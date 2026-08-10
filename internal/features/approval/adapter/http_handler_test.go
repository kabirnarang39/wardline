package adapter_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kabirnarang39/wardline/internal/features/approval/adapter"
	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeMgr struct {
	pending          []domain.Request
	approved, denied string
	err              error
}

func (f *fakeMgr) ListPending(string) []domain.Request { return f.pending }

func (f *fakeMgr) Approve(id, by string) error {
	if f.err != nil {
		return f.err
	}
	f.approved = id
	return nil
}

func (f *fakeMgr) Deny(id, by string) error {
	if f.err != nil {
		return f.err
	}
	f.denied = id
	return nil
}

func TestHTTPHandler_ListPendingLoopback(t *testing.T) {
	mgr := &fakeMgr{pending: []domain.Request{{ID: "1", Tool: "delete"}}}
	h := adapter.NewHTTPHandler(mgr, nil, testLogger)
	req := httptest.NewRequest(http.MethodGet, "/approvals/pending", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"delete"`)
}

func TestHTTPHandler_NonLoopbackForbidden(t *testing.T) {
	h := adapter.NewHTTPHandler(&fakeMgr{}, nil, testLogger)
	req := httptest.NewRequest(http.MethodGet, "/approvals/pending", nil)
	req.RemoteAddr = "10.0.0.5:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHTTPHandler_ApproveLoopback(t *testing.T) {
	mgr := &fakeMgr{}
	h := adapter.NewHTTPHandler(mgr, nil, testLogger)
	req := httptest.NewRequest(http.MethodPost, "/approvals/abc/approve", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "abc", mgr.approved)
}

func TestHTTPHandler_DenyLoopback(t *testing.T) {
	mgr := &fakeMgr{}
	h := adapter.NewHTTPHandler(mgr, nil, testLogger)
	req := httptest.NewRequest(http.MethodPost, "/approvals/xyz/deny", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "xyz", mgr.denied)
}

func TestHTTPHandler_ApproveUnknownIDReturns404(t *testing.T) {
	mgr := &fakeMgr{err: errors.New("unknown or already-decided request")}
	h := adapter.NewHTTPHandler(mgr, nil, testLogger)
	req := httptest.NewRequest(http.MethodPost, "/approvals/nope/approve", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHTTPHandler_NonLoopbackAllowedByAuthorizer(t *testing.T) {
	mgr := &fakeMgr{}
	h := adapter.NewHTTPHandler(mgr, func(*http.Request) bool { return true }, testLogger)
	req := httptest.NewRequest(http.MethodPost, "/approvals/abc/approve", nil)
	req.RemoteAddr = "10.0.0.5:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "abc", mgr.approved)
}
