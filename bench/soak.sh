#!/usr/bin/env bash
# Wardline soak test: sustained moderate load for 30-60 real minutes,
# watching for memory growth, goroutine leaks, or connection pool
# exhaustion -- deliberately separate from bench/run.sh's own fast
# (~5 minute) suite rather than folded into it: bundling a 30-60 minute
# run into the suite every invocation runs would make every routine
# bench/run.sh call take an hour, defeating its purpose as a quick
# regression check. Run this one on its own, occasionally (before a
# release, after a change touching a long-lived goroutine/connection/
# cache), not on every commit.
#
# Samples real runtime stats via WARDLINE_DEBUG_PPROF (cmd/wardline/main.go)
# every SOAK_SAMPLE_INTERVAL seconds: goroutine count
# (/debug/pprof/goroutine?debug=1, counting "goroutine " lines) and heap
# in-use bytes (/debug/pprof/heap?debug=1's inuse_space line), plus
# process RSS via ps as a cross-reference. Writes one CSV row per sample
# to bench/.out/soak-samples.csv, then flags unbounded growth at the end
# by comparing the last quarter of samples' mean against the first
# quarter's (post-warmup) mean -- real leaks grow monotonically past
# GC's own sawtooth, so a sustained large delta between early and late
# means growth, not GC noise.
#
# Run from the repo root: ./bench/soak.sh
# Requires: go, vegeta, curl
set -euo pipefail

DURATION_SECONDS="${SOAK_DURATION_SECONDS:-1800}"   # 30 minutes default; set SOAK_DURATION_SECONDS=3600 for a full hour
RATE="${SOAK_RATE:-150}"                             # moderate, sustainable for the whole run -- not a throughput test
SAMPLE_INTERVAL="${SOAK_SAMPLE_INTERVAL:-30}"        # seconds between runtime-stat samples

OUT="./bench/.out"
BIN="./wardline"
PPROF_ADDR="127.0.0.1:38431"
SAMPLES_CSV="$OUT/soak-samples.csv"

mkdir -p "$OUT"

command -v vegeta >/dev/null || {
  echo "vegeta not found -- install with: go install github.com/tsenart/vegeta@latest" >&2
  exit 1
}

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "== building wardline and httpupstream =="
go build -o "$BIN" ./cmd/wardline
go build -o "$OUT/httpupstream" ./bench/httpupstream

echo "== starting mock HTTP upstream (:39400) =="
"$OUT/httpupstream" 39400 >/dev/null 2>&1 & PIDS+=($!)
sleep 0.3

echo "== starting wardline with WARDLINE_DEBUG_PPROF=$PPROF_ADDR =="
WARDLINE_DEBUG_PPROF="$PPROF_ADDR" "$BIN" serve --config ./bench/soak.yaml >"$OUT/server.soak.log" 2>&1 & SRV=$!
PIDS+=("$SRV")

for _ in $(seq 1 50); do
  curl -s -o /dev/null "http://localhost:38430/healthz" && break
  sleep 0.2
done

echo "== starting sustained load: ${RATE} req/s for ${DURATION_SECONDS}s =="
printf 'POST http://localhost:38430/\n' | \
  vegeta attack -header "X-Wardline-Identity: bench-agent" \
    -header "Content-Type: application/json" \
    -body ./bench/body.json \
    -rate="$RATE" -duration="${DURATION_SECONDS}s" -workers=30 \
  > "$OUT/soak-attack.bin" & ATTACK_PID=$!

echo "sample_unix_time,elapsed_seconds,goroutines,heap_inuse_bytes,rss_kb" > "$SAMPLES_CSV"
START=$(date +%s)
while kill -0 "$ATTACK_PID" 2>/dev/null; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  GOROUTINES=$(curl -s "http://$PPROF_ADDR/debug/pprof/goroutine?debug=1" | head -1 | grep -oE '[0-9]+' | head -1 || echo "")
  HEAP_INUSE=$(curl -s "http://$PPROF_ADDR/debug/pprof/heap?debug=1" | grep '^# HeapInuse' | grep -oE '[0-9]+' || echo "")
  RSS_KB=$(ps -o rss= -p "$SRV" 2>/dev/null | tr -d ' ' || echo "")
  echo "$NOW,$ELAPSED,$GOROUTINES,$HEAP_INUSE,$RSS_KB" >> "$SAMPLES_CSV"
  echo "t+${ELAPSED}s: goroutines=$GOROUTINES heap_inuse_bytes=$HEAP_INUSE rss_kb=$RSS_KB"
  sleep "$SAMPLE_INTERVAL"
done
wait "$ATTACK_PID" 2>/dev/null || true

echo "== attack finished, checking results =="
vegeta report < "$OUT/soak-attack.bin" | tee "$OUT/soak-attack.txt"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "== analyzing $SAMPLES_CSV for growth trends =="
ANALYZE_STATUS=0
go run ./bench/soakanalyze "$SAMPLES_CSV" || ANALYZE_STATUS=$?

echo
echo "== done. Samples: $SAMPLES_CSV -- server log: $OUT/server.soak.log =="
exit "$ANALYZE_STATUS"
