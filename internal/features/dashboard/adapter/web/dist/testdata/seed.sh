#!/usr/bin/env bash
# Seeds a running Wardline instance with a plausible day's worth of mixed
# traffic for dashboard testing: protocol-lifecycle passthrough calls, plus
# allow/deny/throttled tool calls across several identities and tools, then
# a sustained per-identity baseline followed by a sharp burst from one
# identity to trip a real rate-spike/ml_score anomaly and (if
# anomaly.auto_block is configured) a real time-bounded block.
#
# The proxy's own request path lives at "/" (see cmd/wardline/e2e_test.go's
# postToolCall helper and TestServeEndToEnd_DashboardServesWhenEnabled,
# which proxies through http://<addr>/ and reads the dashboard from
# /dashboard/) -- not a placeholder "/mcp" path.
#
# Timing assumes the target instance's anomaly.window_seconds is 5 -- this
# repo's own e2e fixtures use a similarly short window for the same reason
# (see TestServeEndToEnd_MLScoreAutoBlock's window_seconds: 3 and
# TestServeEndToEnd_AnomalyDetectionRateSpike's window_seconds: 3, both with
# ~1s of extra sleep headroom past the window boundary). A longer configured
# window just means the baseline/burst phase below won't land inside single
# windows -- everything else still seeds fine either way.
#
# Requires anomaly_detection on for the anomaly/block paths to do anything;
# harmless no-ops against a plain proxy otherwise. Likewise, seeing any
# "deny" decisions requires policy rules that actually deny some
# identity/tool combos, and seeing any "throttled" decisions requires
# budget_enforcement on with a tight-ish window -- a default: allow policy
# with no budget just means every ordinary call below shows up as "allow".
#
# Usage: ./seed.sh http://localhost:8080
set -euo pipefail
BASE="${1:?usage: seed.sh <base-url>}"

identities=(acme-alice acme-bob acme-carol globex-dave globex-erin)
tools=(search fetch write_file list_dir run_query)

# call posts a raw JSON-RPC body as identity, against the proxy's own
# request path ("/", not "/dashboard/..." -- that's the read-only API the
# dashboard SPA polls, not where traffic is submitted).
call() {
  local identity="$1" body="$2"
  curl -s -o /dev/null -X POST "$BASE/" \
    -H "X-Wardline-Identity: $identity" \
    -H "Content-Type: application/json" \
    -d "$body" || true
}

tool_call() {
  local identity="$1" tool="$2"
  call "$identity" "{\"jsonrpc\":\"2.0\",\"id\":$RANDOM,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
}

echo "Seeding protocol-lifecycle passthrough traffic..."
for identity in "${identities[@]}"; do
  call "$identity" "{\"jsonrpc\":\"2.0\",\"id\":$RANDOM,\"method\":\"initialize\"}"
done

echo "Seeding ordinary mixed traffic (150 calls across 5 identities x 5 tools)..."
for i in $(seq 1 150); do
  identity="${identities[$((RANDOM % ${#identities[@]}))]}"
  tool="${tools[$((RANDOM % ${#tools[@]}))]}"
  tool_call "$identity" "$tool"
done

echo "Establishing acme-alice's baseline over several anomaly windows..."
# 10 windows, not fewer: the anomaly detector's z-score baseline
# (onlineStat.minSamplesForZScore, see
# internal/features/anomaly/usecase/online_stat.go) needs at least 8
# completed windows before ml_score scores anything at all -- below that
# floor, ml_score (and therefore auto_block, which only acts on
# ml_score's value) silently never fires no matter how wild the burst
# below is. 10 keeps the same two-window margin this repo's own
# TestServeEndToEnd_MLScoreAutoBlock e2e fixture uses.
for w in $(seq 1 10); do
  for i in 1 2 3 4; do
    tool_call acme-alice "${tools[$((RANDOM % ${#tools[@]}))]}"
  done
  sleep 5.5 # past a 5s anomaly.window_seconds so this window rolls over and scores
done

echo "Seeding a rate-spike/enumeration burst from acme-alice (may trigger a real anomaly, and a real auto-block if configured)..."
for i in $(seq 1 40); do
  tool_call acme-alice "burst_tool_$i"
done
sleep 5.5 # roll the burst window over so it actually gets scored
tool_call acme-alice search # this call's window-rotation is what scores the burst window

echo "Confirming the block (if auto_block fired above, this call comes back 403)..."
tool_call acme-alice search

echo "Done. Load the dashboard to see the seeded data."
