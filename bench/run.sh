#!/usr/bin/env bash
# Wardline production-scale benchmark suite.
#
# Drives real, sustained concurrent load through a real `wardline serve`
# process with vegeta (HTTP: https://github.com/tsenart/vegeta) and a
# purpose-built raw-gRPC load client (bench/grpcload), covering:
#
#   - the v0.1 baseline hot path (proxy + policy + audit), allow and deny
#   - the same path with every optional feature also on (budget,
#     anomaly detection, credential issuance, gRPC transport), to show
#     the delta each layer of the stack costs
#   - credential issuance (token bootstrap) and Bearer-token verification
#   - budget enforcement actually holding its line under sustained
#     overload (throttled, not fail-open)
#   - the gRPC transport's own passthrough path
#   - unbounded max-throughput: what the proxy itself can sustain, not
#     capped at BENCH_RATE, against a non-bottlenecking upstream
#     (bench/httpupstream, a concurrent Go stand-in -- Python's
#     single-threaded http.server saturates first and muddies the number)
#
# Run from the repo root: ./bench/run.sh
# Requires: go, vegeta (go install github.com/tsenart/vegeta@latest)
set -euo pipefail

RATE="${BENCH_RATE:-500}"      # requests/sec per HTTP scenario
DURATION="${BENCH_DURATION:-15s}"
WORKERS="${BENCH_WORKERS:-50}"
GRPC_CONCURRENCY="${BENCH_GRPC_CONCURRENCY:-50}"
MAX_WORKERS="${BENCH_MAX_WORKERS:-300}"        # concurrency for the unbounded max-throughput scenario
MAXRATE_DURATION="${BENCH_MAXRATE_DURATION:-10s}"
ANOMALY_ATTACK_DURATION="${BENCH_ANOMALY_ATTACK_DURATION:-5s}"  # a real attack is a short burst, not a sustained 15s scenario

OUT="./bench/.out"
BIN="./wardline"
GRPCLOAD="$OUT/grpcload"
HTTPUPSTREAM="$OUT/httpupstream"

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

echo "== building wardline, grpcload, and httpupstream =="
go build -o "$BIN" ./cmd/wardline
go build -o "$GRPCLOAD" ./bench/grpcload
go build -o "$HTTPUPSTREAM" ./bench/httpupstream

echo "== starting mock HTTP upstream (:39400) and mock gRPC upstream (:39401) =="
"$HTTPUPSTREAM" 39400 >/dev/null 2>&1 & PIDS+=($!)
"$GRPCLOAD" upstream :39401 >/dev/null 2>&1 & PIDS+=($!)
sleep 0.3

wait_healthy() {
  local port="$1"
  for _ in $(seq 1 50); do
    curl -s -o /dev/null "http://localhost:$port/healthz" && return 0
    sleep 0.2
  done
  echo "wardline on :$port never became healthy" >&2
  exit 1
}

attack() {
  local name="$1" port="$2" identity="$3"
  printf 'POST http://localhost:%s/\n' "$port" | \
    vegeta attack -header "X-Wardline-Identity: $identity" \
      -header "Content-Type: application/json" \
      -body ./bench/body.json \
      -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
    tee "$OUT/$name.bin" | vegeta report | tee "$OUT/$name.txt"
  echo
}

# attack_tenant is attack() plus X-Wardline-Tenant, for scenarios that need
# to prove a per-tenant budget override holds under load (not just the
# identity/global bucket).
attack_tenant() {
  local name="$1" port="$2" identity="$3" tenant="$4"
  printf 'POST http://localhost:%s/\n' "$port" | \
    vegeta attack -header "X-Wardline-Identity: $identity" \
      -header "X-Wardline-Tenant: $tenant" \
      -header "Content-Type: application/json" \
      -body ./bench/body.json \
      -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
    tee "$OUT/$name.bin" | vegeta report | tee "$OUT/$name.txt"
  echo
}

echo
echo "############################################"
echo "# 1. Baseline (v0.1: proxy + policy + audit) #"
echo "############################################"
"$BIN" serve --config ./bench/wardline.baseline.yaml >"$OUT/server.baseline.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38400

echo "--- allow path ---"
attack baseline-allow 38400 bench-agent
echo "--- deny path ---"
attack baseline-deny 38400 bench-denied-agent

echo "--- allow path, unbounded max throughput (rate=0: fire as fast as $MAX_WORKERS workers can) ---"
printf 'POST http://localhost:38400/\n' | \
  vegeta attack -header "X-Wardline-Identity: bench-agent" \
    -header "Content-Type: application/json" \
    -body ./bench/body.json \
    -rate=0 -max-workers="$MAX_WORKERS" -duration="$MAXRATE_DURATION" | \
  tee "$OUT/baseline-allow-maxrate.bin" | vegeta report | tee "$OUT/baseline-allow-maxrate.txt"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "###########################################################"
echo "# 2. Full stack (budget + anomaly + credential + gRPC on) #"
echo "###########################################################"
"$BIN" serve --config ./bench/wardline.full.yaml >"$OUT/server.full.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38401

echo "--- credential issuance: POST /credentials/token throughput ---"
printf 'POST http://localhost:38401/credentials/token\n' | \
  vegeta attack -header "Content-Type: application/json" \
    -body <(echo '{"secret":"bench-only-secret-do-not-use-in-production-0123456789"}') \
    -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/full-credential-issuance.bin" | vegeta report | tee "$OUT/full-credential-issuance.txt"

echo "--- allow path, full feature stack (Bearer token, credential_issuance is on so a raw X-Wardline-Identity header is no longer trusted) ---"
TOKEN=$(curl -s -X POST http://localhost:38401/credentials/token \
  -H "Content-Type: application/json" \
  -d '{"secret":"bench-only-secret-do-not-use-in-production-0123456789"}' | jq -r .token)
printf 'POST http://localhost:38401/\nAuthorization: Bearer %s\n' "$TOKEN" | \
  vegeta attack -header "Content-Type: application/json" \
    -body ./bench/body.json \
    -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/full-allow.bin" | vegeta report | tee "$OUT/full-allow.txt"

echo "--- gRPC transport passthrough (Bearer token, same reason as the HTTP allow path above) ---"
sleep 0.5 # grpc_listen starts alongside the HTTP listener; healthz above only proves the latter is up
"$GRPCLOAD" load "localhost:38402" bench-agent "$GRPC_CONCURRENCY" "$DURATION" "$TOKEN" | tee "$OUT/full-grpc.txt"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "############################################################"
echo "# 3. Budget enforcement: 100 req/window/1s, load exceeds it #"
echo "############################################################"
"$BIN" serve --config ./bench/wardline.budget-throttle.yaml >"$OUT/server.budget.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38403

attack budget-throttle 38403 bench-agent

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "#####################################################################"
echo "# 4. Budget tenant-override AND-semantics: global default is huge   #"
echo "#    (never throttles alone); only acme's tenant override (100/1s)  #"
echo "#    can produce the throttling below -- proves the tenant bucket   #"
echo "#    is consulted in addition to, not instead of, the identity      #"
echo "#    bucket under real concurrent load.                             #"
echo "#####################################################################"
"$BIN" serve --config ./bench/wardline.budget-tenant-override.yaml >"$OUT/server.budget-tenant-override.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38404

attack_tenant budget-tenant-override 38404 bench-agent acme

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "###############################################################"
echo "# 5. Credential issuance: oidc bootstrap source (mock IdP+JWKS) #"
echo "###############################################################"
OIDCIDP="$OUT/oidcidp"
go build -o "$OIDCIDP" ./bench/oidcidp
OIDC_TOKEN_FILE="$OUT/oidc-idtoken.txt"
# Removed first, not just overwritten: $OUT persists across runs, so a
# stale token file from a PREVIOUS invocation (signed by that run's own
# throwaway RSA key, which oidcidp regenerates fresh every start) would
# otherwise satisfy the "-s FILE" wait check below immediately -- read
# before this run's oidcidp has written its own token, or read the whole
# stale file outright when this run's write happens to trail the check.
# The wardline instance below fetches JWKS from THIS run's oidcidp, so a
# stale token (signed by a different key than what's in that JWKS)
# fails signature verification on every single request -- the bug this
# comment documents, found by the load-testing pass itself.
rm -f "$OIDC_TOKEN_FILE"
"$OIDCIDP" "localhost:39402" "https://oidcidp.bench.example.com/" "wardline-bench" "$OIDC_TOKEN_FILE" >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 50); do [ -s "$OIDC_TOKEN_FILE" ] && break; sleep 0.1; done
[ -s "$OIDC_TOKEN_FILE" ] || { echo "oidcidp never wrote its token file" >&2; exit 1; }
OIDC_ID_TOKEN=$(cat "$OIDC_TOKEN_FILE")

"$BIN" serve --config ./bench/wardline.oidc.yaml >"$OUT/server.oidc.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38405

echo "--- oidc bootstrap: POST /credentials/token throughput ---"
printf 'POST http://localhost:38405/credentials/token\n' | \
  vegeta attack -header "Content-Type: application/json" \
    -body <(printf '{"secret":"%s"}' "$OIDC_ID_TOKEN") \
    -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/oidc-credential-issuance.bin" | vegeta report | tee "$OUT/oidc-credential-issuance.txt"
echo

echo "--- allow path with an oidc-bootstrapped bearer token ---"
OIDC_BEARER=$(curl -s -X POST http://localhost:38405/credentials/token \
  -H "Content-Type: application/json" \
  -d "$(printf '{"secret":"%s"}' "$OIDC_ID_TOKEN")" | jq -r .token)
printf 'POST http://localhost:38405/\nAuthorization: Bearer %s\n' "$OIDC_BEARER" | \
  vegeta attack -header "Content-Type: application/json" \
    -body ./bench/body.json \
    -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/oidc-allow.bin" | vegeta report | tee "$OUT/oidc-allow.txt"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "###################################################################"
echo "# 6. Credential issuance: mtls (header-based) bootstrap source     #"
echo "###################################################################"
"$BIN" serve --config ./bench/wardline.mtls.yaml >"$OUT/server.mtls.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38406

MTLS_SPIFFE_ID="spiffe://bench.example.com/ns/default/sa/bench-agent"

echo "--- mtls bootstrap: POST /credentials/token throughput (trusted header set by the terminating mesh) ---"
printf 'POST http://localhost:38406/credentials/token\nX-Wardline-Verified-Spiffe-Id: %s\n' "$MTLS_SPIFFE_ID" | \
  vegeta attack -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/mtls-credential-issuance.bin" | vegeta report | tee "$OUT/mtls-credential-issuance.txt"
echo

echo "--- allow path with an mtls-bootstrapped bearer token ---"
MTLS_BEARER=$(curl -s -X POST http://localhost:38406/credentials/token \
  -H "X-Wardline-Verified-Spiffe-Id: $MTLS_SPIFFE_ID" | jq -r .token)
printf 'POST http://localhost:38406/\nAuthorization: Bearer %s\n' "$MTLS_BEARER" | \
  vegeta attack -header "Content-Type: application/json" \
    -body ./bench/body.json \
    -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/mtls-allow.bin" | vegeta report | tee "$OUT/mtls-allow.txt"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "###################################################################"
echo "# 7. RBAC: role-binding-gated dashboard authorization under load   #"
echo "###################################################################"
"$BIN" serve --config ./bench/wardline.rbac.yaml >"$OUT/server.rbac.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38407

attack_get_identity() {
  local name="$1" port="$2" identity="$3"
  printf 'GET http://localhost:%s/dashboard/api/status\n' "$port" | \
    vegeta attack -header "X-Wardline-Identity: $identity" \
      -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
    tee "$OUT/$name.bin" | vegeta report | tee "$OUT/$name.txt"
  echo
}

echo "--- bench-viewer (bound to role viewer): dashboard access allowed ---"
attack_get_identity rbac-allowed 38407 bench-viewer

echo "--- bench-noaccess (unbound): dashboard access denied ---"
attack_get_identity rbac-denied 38407 bench-noaccess

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "###################################################################"
echo "# 8. Anomaly detection: real attack-shaped load, confirm auto_block #"
echo "###################################################################"
ANOMALYATTACK="$OUT/anomalyattack"
go build -o "$ANOMALYATTACK" ./bench/anomalyattack
"$BIN" serve --config ./bench/wardline.anomaly-attack.yaml >"$OUT/server.anomaly-attack.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38408

"$ANOMALYATTACK" localhost:38408 attack-agent 3 50 "$ANOMALY_ATTACK_DURATION"
ANOMALYATTACK_STATUS=$?

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

if [ "$ANOMALYATTACK_STATUS" -ne 0 ]; then
  echo "anomalyattack scenario FAILED (auto_block did not fire under load) -- see $OUT/anomaly.anomaly-attack.jsonl and $OUT/server.anomaly-attack.log" >&2
  exit 1
fi

echo
echo "###################################################################"
echo "# 9. gRPC transport with TLS on: spiffe_workload_identity + real   #"
echo "#    mutual TLS to the upstream, under load                        #"
echo "###################################################################"
SPIFFEIDP="$OUT/spiffeidp"
go build -o "$SPIFFEIDP" ./bench/spiffeidp
SPIFFE_SOCKET="/tmp/wardline-bench-spiffe-workload.sock"
UPSTREAM_CERT="$OUT/grpc-tls-upstream-cert.pem"
UPSTREAM_KEY="$OUT/grpc-tls-upstream-key.pem"
CA_CERT="$OUT/grpc-tls-ca-cert.pem"
rm -f "$SPIFFE_SOCKET" # stale socket from a prior run -- see bench/spiffeidp's own os.Remove for why the server side also does this

"$SPIFFEIDP" "$SPIFFE_SOCKET" "spiffe://bench.example.com/wardline" "spiffe://bench.example.com/upstream" \
  "$UPSTREAM_CERT" "$UPSTREAM_KEY" "$CA_CERT" >"$OUT/spiffeidp.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 50); do [ -S "$SPIFFE_SOCKET" ] && break; sleep 0.1; done
[ -S "$SPIFFE_SOCKET" ] || { echo "spiffeidp never created its workload API socket" >&2; exit 1; }

"$GRPCLOAD" upstream :39403 "$UPSTREAM_CERT" "$UPSTREAM_KEY" "$CA_CERT" >"$OUT/grpc-tls-upstream.log" 2>&1 & PIDS+=($!)
sleep 0.3

"$BIN" serve --config ./bench/wardline.grpc-tls.yaml >"$OUT/server.grpc-tls.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38409
sleep 0.5 # grpc_listen starts alongside the HTTP listener, same reason scenario 2's grpc run has this

"$GRPCLOAD" load "localhost:38410" bench-agent "$GRPC_CONCURRENCY" "$DURATION" | tee "$OUT/grpc-tls.txt"

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

echo
echo "###################################################################"
echo "# 10. SCIM: Bulk operations and filter queries under load          #"
echo "###################################################################"
SCIMLOAD="$OUT/scimload"
go build -o "$SCIMLOAD" ./bench/scimload
export WARDLINE_BENCH_SCIM_TOKEN="bench-only-scim-token-do-not-use-in-production"
"$BIN" serve --config ./bench/wardline.scim.yaml >"$OUT/server.scim.log" 2>&1 & SRV=$!
PIDS+=("$SRV")
wait_healthy 38411

echo "--- pre-seeding 50 users for the filter-query load below ---"
for i in $(seq 1 50); do
  active=true
  [ $((i % 3)) -eq 0 ] && active=false
  curl -s -o /dev/null -X POST "http://localhost:38411/scim/v2/Users" \
    -H "Authorization: Bearer $WARDLINE_BENCH_SCIM_TOKEN" \
    -H "Content-Type: application/scim+json" \
    -d "{\"userName\":\"scim-seed-user-$i\",\"active\":$active}"
done

echo "--- filter query: GET /scim/v2/Users?filter=active eq true ---"
printf 'GET http://localhost:38411/scim/v2/Users?filter=active%%20eq%%20true\nAuthorization: Bearer %s\n' "$WARDLINE_BENCH_SCIM_TOKEN" | \
  vegeta attack -rate="$RATE" -duration="$DURATION" -workers="$WORKERS" | \
  tee "$OUT/scim-filter-query.bin" | vegeta report | tee "$OUT/scim-filter-query.txt"
echo

echo "--- Bulk create operations (5 Creates per Bulk request, unique userNames) ---"
"$SCIMLOAD" localhost:38411 "$WARDLINE_BENCH_SCIM_TOKEN" "$WORKERS" "$DURATION" 5
SCIMLOAD_STATUS=$?

kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true

if [ "$SCIMLOAD_STATUS" -ne 0 ]; then
  echo "scimload scenario FAILED (a Bulk operation failed under load) -- see $OUT/server.scim.log" >&2
  exit 1
fi

echo
echo "== done. Raw vegeta reports + server/anomaly/audit logs under $OUT/ =="
