package adapter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// Handler is the HTTP entry point: parse each request, ask the Decider for
// a verdict, record exactly one audit entry per request, and forward
// allowed calls to the upstream MCP server.
type Handler struct {
	decider  *proxyusecase.Decider
	recorder *auditusecase.Recorder
	upstream *httputil.ReverseProxy
	now      func() time.Time
}

func NewHandler(decider *proxyusecase.Decider, recorder *auditusecase.Recorder, upstream *url.URL) *Handler {
	return &Handler{
		decider:  decider,
		recorder: recorder,
		upstream: httputil.NewSingleHostReverseProxy(upstream),
		now:      time.Now,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	identity := r.Header.Get("X-Wardline-Identity")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.record(identity, "", "error", start)
		http.Error(w, `{"error":"cannot read body"}`, http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	call, err := proxyusecase.ParseToolCall(identity, body)
	if err != nil {
		h.record(identity, "", "error", start)
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	verdict := h.decider.Decide(call)
	if !verdict.Allow {
		h.record(identity, call.Tool, "deny", start)
		http.Error(w, fmt.Sprintf(`{"error":"denied: %s"}`, verdict.Reason), http.StatusForbidden)
		return
	}

	h.forward(w, r, identity, call.Tool, start)
}

// forward proxies the request upstream, recording exactly one audit entry
// depending on whether the upstream call succeeded or failed.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, identity, tool string, start time.Time) {
	proxy := *h.upstream // shallow copy: per-request ErrorHandler/ModifyResponse closures
	recorded := false
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		recorded = true
		h.record(identity, tool, "error", start)
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !recorded {
			h.record(identity, tool, "allow", start)
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

func (h *Handler) record(identity, tool, decision string, start time.Time) {
	h.recorder.Record(identity, tool, decision, h.now().Sub(start), start)
}
