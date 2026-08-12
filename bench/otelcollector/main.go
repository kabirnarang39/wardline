// Command otelcollector is a minimal mock OTLP/HTTP collector for
// benchmarking otel_tracing's export overhead under load: accepts any
// POST (the real otlptracehttp exporter posts to /v1/traces) and
// returns 200 immediately, discarding the body -- stands in for a real
// collector the same way bench/httpupstream stands in for a real MCP
// server, so the numbers measure wardline's own span-generation/export
// overhead, not a real collector's ingestion cost.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":39500"
	if len(os.Args) > 1 {
		addr = ":" + os.Args[1]
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	log.Printf("otelcollector accepting OTLP/HTTP exports on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil { //nolint:gosec // bench-only loopback stand-in, not internet-facing
		log.Fatal(err)
	}
}
