// Command mock_mcp is a minimal, spec-shaped MCP server used only as
// Wardline's upstream inside the Glama automated-check container (see
// ../Dockerfile). Glama's checker needs something real behind Wardline to
// introspect -- Wardline itself is a proxy, not a tool server, so a bare
// "wardline" container with no upstream 502s on every call. This stub
// exists purely to give that check something valid to talk to.
//
// Not part of the production build, not imported by anything under
// internal/, and not what any real deployment should point Wardline at.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type rpcRequest struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req rpcRequest
	_ = json.Unmarshal(body, &req)

	// A notification (no "id") gets no response body -- per JSON-RPC and
	// the MCP spec, notifications/initialized is exactly this case.
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		writeResult(w, req.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "wardline-glama-stub", "version": "0.1.0"},
		})
	case "tools/list":
		writeResult(w, req.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "ping",
					"description": "Returns \"pong\". Stub tool that exists only so an automated MCP-introspection check has one real tool to see and call.",
					"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
				},
			},
		})
	case "tools/call":
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": "pong"}},
		})
	default:
		writeResult(w, req.ID, map[string]any{})
	}
}

func main() {
	addr := "127.0.0.1:9000"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	http.HandleFunc("/", handle)
	log.Printf("mock_mcp listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil { //nolint:gosec // loopback-only fixture, not internet-facing
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
