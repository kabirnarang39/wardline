#!/usr/bin/env bash
# Wardline live demo: an allowed agent behaves, gets compromised, trips
# statistical anomaly detection, and Wardline AUTO-BLOCKS it in real time --
# no rule written for the attack, no human in the loop.
#
# Run from the repo root:  ./demo/run.sh   (or: make demo)
set -euo pipefail

WL_PORT="${WL_PORT:-38300}"
UP_PORT="${UP_PORT:-39300}"
BIN="./wardline"
OUT="./demo/.out"

# ---- colors ----
B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; RST=$'\e[0m'
banner() { printf '\n%s%s%s\n' "$B$C" "$1" "$RST"; }
ok()     { printf '  %sALLOW%s  %s\n' "$G$B" "$RST" "$1"; }
deny()   { printf '  %sDENY %s  %s\n' "$R$B" "$RST" "$1"; }
block()  { printf '  %sBLOCK%s  %s\n' "$R$B" "$RST" "$1"; }

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  [[ -n "${UP_PID:-}"  ]] && kill "$UP_PID"  2>/dev/null || true
}
trap cleanup EXIT

# CALL <identity> <tool> -> echoes the HTTP status code
CALL() {
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$WL_PORT/" \
    -H "X-Wardline-Identity: $1" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"$2\"}}"
}

mkdir -p "$OUT"; : > "$OUT/audit.jsonl"; : > "$OUT/anomaly.jsonl"

if [[ ! -x "$BIN" ]]; then
  banner "Building wardline..."
  go build -o "$BIN" ./cmd/wardline
fi

banner "Starting the mock MCP upstream and Wardline..."
python3 ./demo/mock_mcp.py "$UP_PORT" >/dev/null 2>&1 & UP_PID=$!
"$BIN" serve --config ./demo/wardline.demo.yaml >"$OUT/server.log" 2>&1 & SRV_PID=$!
# wait for the proxy to actually accept connections before the first call
for _ in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:$WL_PORT/healthz" && break || sleep 0.2
done
printf '  %sWardline proxy on :%s   MCP upstream on :%s%s\n' "$DIM" "$WL_PORT" "$UP_PORT" "$RST"

banner "1) Policy: shopper-bot may call only its two allowed tools"
printf '  %sagent %sshopper-bot%s%s doing normal work%s\n' "$DIM" "$B" "$RST" "$DIM" "$RST"
ok "search_products  -> $(CALL shopper-bot search_products)"
ok "get_price        -> $(CALL shopper-bot get_price)"
printf '  %sthen it reaches for a tool it was never granted%s\n' "$DIM" "$RST"
deny "admin_delete_all -> $(CALL shopper-bot admin_delete_all)  (blocked by policy)"

banner "2) Wardline learns shopper-bot's normal behavior (self-baselining)"
printf '  '
for w in $(seq 1 9); do
  CALL shopper-bot search_products >/dev/null
  CALL shopper-bot get_price >/dev/null
  CALL shopper-bot search_products >/dev/null
  printf '%s#%s' "$G" "$RST"; sleep 1.02
done
printf '  baseline established\n'

banner "3) shopper-bot is COMPROMISED -- it starts hammering the API"
printf '  %s30 rapid calls to a tool it should never touch...%s\n' "$R" "$RST"
for i in $(seq 1 30); do CALL shopper-bot exfiltrate_data >/dev/null; done
sleep 1.05
CALL shopper-bot search_products >/dev/null   # trigger scoring of the burst window

banner "4) Wardline detected the anomaly and ACTED -- no rule, no human"
ml=$(grep '"kind":"ml_score"' "$OUT/anomaly.jsonl" | tail -1 \
     | sed -E 's/.*"detail":"([^"]+)".*/\1/')
printf '  %sanomaly:%s %s\n' "$Y$B" "$RST" "${ml:-ml_score threshold exceeded}"
printf '  %s-> auto-block engaged for shopper-bot%s\n' "$R$B" "$RST"

banner "5) The payoff: shopper-bot's next call -- even a legitimate one"
code=$(CALL shopper-bot search_products)
if [[ "$code" == "403" ]]; then
  block "search_products -> 403  (identity auto-blocked; even its allowed tools are refused)"
else
  printf '  got HTTP %s (expected 403 -- see %s)\n' "$code" "$OUT/server.log"
fi
printf '  %seven the MCP handshake is refused while blocked:%s\n' "$DIM" "$RST"
init=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$WL_PORT/" \
        -H "X-Wardline-Identity: shopper-bot" \
        -d '{"jsonrpc":"2.0","method":"initialize","params":{}}')
[[ "$init" == "403" ]] && block "initialize      -> 403  (a blocked identity gets no handshake)"

banner "Evidence -- every decision is in the audit + anomaly logs"
printf '  audit  blocked entries : %s%s%s\n' "$B" "$(grep -c '"decision":"blocked"' "$OUT/audit.jsonl")" "$RST"
printf '  anomaly log kinds      : %s%s%s\n' "$B" \
  "$(grep -o '"kind":"[a-z_]*"' "$OUT/anomaly.jsonl" | sort | uniq -c | awk '{printf "%s(%s) ", $2, $1}')" "$RST"
printf '\n  %sThe block is time-bounded (%ss) and lifts on its own -- no manual unblock.%s\n' "$DIM" "8" "$RST"
printf '  %sSingle static Go binary. No database, no IdP, no sidecar.%s\n\n' "$DIM" "$RST"
