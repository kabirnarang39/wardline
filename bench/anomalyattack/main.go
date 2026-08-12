// Command anomalyattack drives a real attack-shaped load pattern at a
// running wardline serve to prove auto_block fires under real concurrent
// traffic, not just the single-threaded sequential calls
// TestServeEndToEnd_MLScoreAutoBlock uses at the unit/e2e level.
//
// Three phases:
//
//  1. baseline: sequential, low-variance calls across several rotated
//     anomaly windows, establishing the identity's mlStats baseline
//     (mirrors the e2e test's baseline-building loop).
//  2. attack: <concurrency> workers hammering wardline for <duration>,
//     each request either a distinct never-seen-before tool name (novel
//     tool burst) or a call to a policy-denied tool (deny-rate spike) --
//     the combined volumetric+diversity+deny-rate burst that drives
//     ml_score, all fired concurrently, not one at a time.
//  3. probe: after the attack window rotates and scores, one more call
//     confirms whether auto_block actually blocked the identity.
//
// Usage:
//
//	anomalyattack <wardline-addr> <identity> <window-seconds> <concurrency> <attack-duration>
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// restrictedTool is the tool bench/policy.anomaly-attack.yaml denies for
// the attacking identity -- every call to it during the attack phase
// feeds the deny-rate-spike heuristic.
const restrictedTool = "restricted_tool"

var httpClient = &http.Client{
	Transport: &http.Transport{MaxIdleConnsPerHost: 256},
	Timeout:   5 * time.Second,
}

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: anomalyattack <wardline-addr> <identity> <window-seconds> <concurrency> <attack-duration>")
		os.Exit(2)
	}
	addr, identity := os.Args[1], os.Args[2]
	windowSeconds, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad window-seconds:", err)
		os.Exit(2)
	}
	concurrency, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad concurrency:", err)
		os.Exit(2)
	}
	attackDuration, err := time.ParseDuration(os.Args[5])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad attack-duration:", err)
		os.Exit(2)
	}
	window := time.Duration(windowSeconds) * time.Second
	rotate := window + 1100*time.Millisecond // headroom past the window boundary, same margin the e2e tests use

	url := "http://" + addr + "/"

	fmt.Println("== phase 1: baseline (sequential, building mlStats) ==")
	// 10 rounds, alternating 2 vs 3 calls and 1 vs 2 tools, mirrors
	// TestServeEndToEnd_MLScoreAutoBlock's baseline shape so the
	// established mean/stddev has real, non-zero variance to compare
	// the attack window against.
	for range 5 {
		mustCall(url, identity, "read_file")
		mustCall(url, identity, "read_file")
		time.Sleep(rotate)
		mustCall(url, identity, "read_file")
		mustCall(url, identity, "list_dir")
		mustCall(url, identity, "list_dir")
		time.Sleep(rotate)
	}

	fmt.Printf("== phase 2: attack (%d concurrent workers for %s: novel-tool burst + deny-rate spike) ==\n", concurrency, attackDuration)
	var okCount, denyCount, errCount int64
	var toolCounter atomic.Int64
	latencies := make(chan time.Duration, 1<<20)
	deadline := time.Now().Add(attackDuration)

	var wg sync.WaitGroup
	for w := range concurrency {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				n := toolCounter.Add(1)
				var tool string
				if n%4 == 0 {
					// Deny-rate spike: a real policy-denied tool, not a
					// synthetic 403 -- confirms the heuristic reacts to
					// actual audit deny decisions under load.
					tool = restrictedTool
				} else {
					// Novel-tool burst: every call names a tool this
					// identity has never called before, unlimited
					// cardinality, the classic enumeration/exfiltration
					// shape.
					tool = fmt.Sprintf("attack_tool_%d_%d", workerID, n)
				}
				start := time.Now()
				status, err := call(url, identity, tool)
				elapsed := time.Since(start)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				latencies <- elapsed
				switch status {
				case http.StatusOK:
					atomic.AddInt64(&okCount, 1)
				case http.StatusForbidden:
					atomic.AddInt64(&denyCount, 1)
				default:
					atomic.AddInt64(&errCount, 1)
				}
			}
		}(w)
	}
	wg.Wait()
	close(latencies)

	all := make([]time.Duration, 0, len(latencies))
	for l := range latencies {
		all = append(all, l)
	}
	slices.Sort(all)

	total := okCount + denyCount + errCount
	fmt.Printf("attack requests: %d (allowed=%d denied=%d errored=%d)\n", total, okCount, denyCount, errCount)
	fmt.Printf("attack throughput: %.1f req/s\n", float64(total)/attackDuration.Seconds())
	if len(all) > 0 {
		fmt.Printf("attack latency p50=%v p95=%v p99=%v max=%v\n",
			percentile(all, 0.50), percentile(all, 0.95), percentile(all, 0.99), all[len(all)-1])
	}

	fmt.Println("== phase 3: probe (waiting for the attack window to rotate and score) ==")
	time.Sleep(rotate)
	// This first call's own Publish is what rotates and scores the
	// attack window -- BlockChecker.Block (if the score clears
	// auto_block.score_threshold) runs synchronously inside that
	// Publish, but AFTER this same request's own block check already
	// passed (see internal/features/proxy/adapter/handler.go: the block
	// check runs before Publish). So this call is expected to succeed
	// regardless; it's the NEXT call that proves whether auto_block
	// fired. Mirrors TestServeEndToEnd_MLScoreAutoBlock's doCall-then-
	// blockedResp shape exactly.
	if _, err := call(url, identity, "read_file"); err != nil {
		fmt.Fprintln(os.Stderr, "scoring call failed:", err)
		os.Exit(1)
	}
	status, err := call(url, identity, "read_file")
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe call failed:", err)
		os.Exit(1)
	}
	if status == http.StatusForbidden {
		fmt.Println("AUTO_BLOCK: TRIGGERED (probe call correctly denied post-attack)")
	} else {
		fmt.Printf("AUTO_BLOCK: NOT TRIGGERED (probe call returned %d, expected 403)\n", status)
		os.Exit(1)
	}
}

// mustCall is call, ignoring the response -- used only for the baseline
// phase, where every call is expected to succeed and only its side
// effect (feeding the identity's mlStats) matters, not its status code.
func mustCall(url, identity, tool string) {
	if _, err := call(url, identity, tool); err != nil {
		fmt.Fprintln(os.Stderr, "baseline call failed:", err)
		os.Exit(1)
	}
}

func call(url, identity, tool string) (int, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q}}`, tool)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Wardline-Identity", identity)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
