// Command httpupstream is a concurrent mock MCP upstream for benchmarking,
// standing in for demo/mock_mcp.py: same trivial JSON-RPC-shaped 200
// response, but Go's net/http server handles each connection on its own
// goroutine, so it doesn't become the bottleneck the way Python's
// single-threaded http.server does under a max-throughput attack. The
// point of that benchmark is Wardline's own overhead, not this stand-in's.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":39400"
	if len(os.Args) > 1 {
		addr = ":" + os.Args[1]
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     any `json:"id"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  map[string]any{"tool": req.Params.Name, "ok": true},
		})
	})
	log.Printf("httpupstream echoing on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil { //nolint:gosec // bench-only loopback stand-in, not internet-facing
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
