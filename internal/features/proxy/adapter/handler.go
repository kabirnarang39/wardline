package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// JSON-RPC error codes used for v0.1. This isn't a full JSON-RPC error code
// taxonomy — just enough to distinguish "we couldn't understand the
// request" from "we understood it and something downstream went wrong".
const (
	rpcCodeParseError = -32700 // malformed/oversized/unparsable request body
	rpcCodeServerErr  = -32000 // policy deny or upstream failure (reserved server-error range)
)

type jsonRPCErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCErrorResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Error   jsonRPCErrorBody `json:"error"`
}

// writeJSONRPCError writes a valid, labeled JSON-RPC 2.0 error envelope
// instead of a plain-text body, so callers get a parseable error shape
// consistent with the protocol they spoke to reach us.
func writeJSONRPCError(w http.ResponseWriter, status, code int, id json.RawMessage, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonRPCErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   jsonRPCErrorBody{Code: code, Message: message},
	})
}

// upstreamResponseHeaderTimeout bounds how long we wait for a connected
// upstream to start responding; MCP tool calls are fast, so 30s is generous.
const upstreamResponseHeaderTimeout = 30 * time.Second

// maxRequestBodyBytes caps how much of the request body we'll read before
// any policy check runs; MCP tool-call payloads are small JSON-RPC
// envelopes, so 1 MiB is generous headroom, not a real limit in practice.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

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
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// Clone http.DefaultTransport rather than starting from a zero-value
	// &http.Transport{} so we keep its dial/TLS-handshake timeouts, HTTP/2
	// support, connection pooling, and Proxy: ProxyFromEnvironment — only
	// ResponseHeaderTimeout is overridden.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = upstreamResponseHeaderTimeout
	proxy.Transport = tr
	return &Handler{
		decider:  decider,
		recorder: recorder,
		upstream: proxy,
		now:      time.Now,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	identity := r.Header.Get("X-Wardline-Identity")

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.record(identity, "", "error", start)
		writeJSONRPCError(w, http.StatusBadRequest, rpcCodeParseError, nil, "cannot read body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	call, id, err := proxyusecase.ParseToolCall(identity, body)
	if err != nil {
		h.record(identity, "", "error", start)
		writeJSONRPCError(w, http.StatusBadRequest, rpcCodeParseError, id, err.Error())
		return
	}
	call.Timestamp = start
	call.RemoteAddr = r.RemoteAddr
	call.UserAgent = r.Header.Get("User-Agent")

	verdict := h.decider.Decide(call)
	if !verdict.Allow {
		h.record(identity, call.Tool, "deny", start)
		writeJSONRPCError(w, http.StatusForbidden, rpcCodeServerErr, id, fmt.Sprintf("denied: %s", verdict.Reason))
		return
	}

	h.forward(w, r, identity, call.Tool, id, start)
}

// forward proxies the request upstream, recording exactly one audit entry
// depending on whether the upstream call succeeded or failed.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, identity, tool string, id json.RawMessage, start time.Time) {
	proxy := *h.upstream // shallow copy: per-request ErrorHandler/ModifyResponse closures
	recorded := false
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		recorded = true
		h.record(identity, tool, "error", start)
		writeJSONRPCError(w, http.StatusBadGateway, rpcCodeServerErr, id, "upstream unreachable")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !recorded {
			recorded = true
			h.record(identity, tool, "allow", start)
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

func (h *Handler) record(identity, tool, decision string, start time.Time) {
	h.recorder.Record(identity, tool, decision, h.now().Sub(start), start)
}
