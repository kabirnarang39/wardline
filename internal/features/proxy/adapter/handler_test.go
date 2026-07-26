package adapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// jsonRPCErrorEnvelope mirrors the shape written by writeJSONRPCError, for
// asserting on error response bodies from outside the package.
type jsonRPCErrorEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeJSONRPCError(t *testing.T, w *httptest.ResponseRecorder) jsonRPCErrorEnvelope {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
	var env jsonRPCErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body: %s)", err, w.Body.String())
	}
	if env.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", env.JSONRPC)
	}
	return env
}

type fakeEngine struct {
	effect policydomain.Effect
}

func (f fakeEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	return policydomain.Decision{Effect: f.effect, Reason: "fake"}
}

type fakeWriter struct {
	entries []auditdomain.Entry
}

func (f *fakeWriter) Write(e auditdomain.Entry) error {
	f.entries = append(f.entries, e)
	return nil
}

type contextRecordingEngine struct {
	received policydomain.Context
}

func (e *contextRecordingEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	e.received = ctx
	return policydomain.Decision{Effect: policydomain.EffectAllow, Reason: "fake"}
}

func newRequest(identity, tool string) *http.Request {
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + tool + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("X-Wardline-Identity", identity)
	return req
}

func TestHandler_AllowedCallReachesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
}

func TestHandler_DeniedCallNeverReachesUpstream(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectDeny})
	handler := adapter.NewHandler(decider, recorder, upstreamURL)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream should not have been called for a denied request")
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "deny" {
		t.Fatalf("expected one deny audit entry, got %+v", writer.entries)
	}
	env := decodeJSONRPCError(t, w)
	if env.Error.Message == "" {
		t.Error("expected a non-empty error message")
	}
}

func TestHandler_UpstreamUnreachableReturnsError(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1") // nothing listens here

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
	decodeJSONRPCError(t, w)
}

func TestHandler_MalformedBodyReturnsError(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("not json"))
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
	env := decodeJSONRPCError(t, w)
	if string(env.ID) != "null" {
		t.Errorf("expected null id for unparsable body, got %s", env.ID)
	}
}

func TestHandler_OversizedBodyRejected(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL)

	// One byte over the 1 MiB cap; content doesn't matter since the reader
	// should be cut off before the body is parsed as JSON.
	oversized := bytes.Repeat([]byte("a"), (1<<20)+1)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(oversized))
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
	decodeJSONRPCError(t, w)
}

func TestHandler_PopulatesContextFromRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil)
	engine := &contextRecordingEngine{}
	decider := proxyusecase.NewDecider(engine)
	handler := adapter.NewHandler(decider, recorder, upstreamURL)

	before := time.Now()
	req := newRequest("agent-abc123", "read_file")
	req.Header.Set("User-Agent", "wardline-test-agent/1.0")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	after := time.Now()

	if engine.received.RemoteAddr == "" {
		t.Error("expected non-empty RemoteAddr on the Context passed to the policy engine")
	}
	if engine.received.UserAgent != "wardline-test-agent/1.0" {
		t.Errorf("expected UserAgent to be forwarded, got %q", engine.received.UserAgent)
	}
	if engine.received.Timestamp.Before(before) || engine.received.Timestamp.After(after) {
		t.Errorf("expected Timestamp between %v and %v, got %v", before, after, engine.received.Timestamp)
	}
}
