// Command scimload drives concurrent SCIM Bulk create load at a running
// wardline serve. Unlike the filter-query GET path (idempotent, safe to
// replay the same vegeta body every request), a Bulk batch of Create
// operations MUST carry unique userNames per request past the first --
// vegeta's single static -body file can't express that, so this is a
// dedicated concurrent client instead, same reasoning as
// bench/anomalyattack and bench/grpcload's own load modes.
//
// Usage: scimload <wardline-addr> <bearer-token> <concurrency> <duration> <ops-per-bulk-request>
package main

import (
	"encoding/json"
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

var httpClient = &http.Client{
	Transport: &http.Transport{MaxIdleConnsPerHost: 256},
	Timeout:   5 * time.Second,
}

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: scimload <wardline-addr> <bearer-token> <concurrency> <duration> <ops-per-bulk-request>")
		os.Exit(2)
	}
	addr, bearerToken := os.Args[1], os.Args[2]
	concurrency, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad concurrency:", err)
		os.Exit(2)
	}
	duration, err := time.ParseDuration(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad duration:", err)
		os.Exit(2)
	}
	opsPerRequest, err := strconv.Atoi(os.Args[5])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad ops-per-bulk-request:", err)
		os.Exit(2)
	}

	url := "http://" + addr + "/scim/v2/Bulk"
	var okCount, errCount atomic.Int64
	var counter atomic.Int64
	latencies := make(chan time.Duration, 1<<20)
	deadline := time.Now().Add(duration)

	var wg sync.WaitGroup
	for w := range concurrency {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				body := buildBulkRequest(workerID, counter.Add(1), opsPerRequest)
				start := time.Now()
				status, respBody, err := post(url, bearerToken, body)
				elapsed := time.Since(start)
				if err != nil || status != http.StatusOK || !allOperationsSucceeded(respBody) {
					errCount.Add(1)
					continue
				}
				okCount.Add(1)
				latencies <- elapsed
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

	total := okCount.Load() + errCount.Load()
	totalOps := total * int64(opsPerRequest)
	fmt.Printf("bulk requests: %d (ok=%d err=%d), %d Create operations total\n", total, okCount.Load(), errCount.Load(), totalOps)
	fmt.Printf("throughput: %.1f bulk-requests/s (%.1f Create ops/s)\n", float64(okCount.Load())/duration.Seconds(), float64(okCount.Load()*int64(opsPerRequest))/duration.Seconds())
	if len(all) > 0 {
		fmt.Printf("latency p50=%v p95=%v p99=%v max=%v\n",
			percentile(all, 0.50), percentile(all, 0.95), percentile(all, 0.99), all[len(all)-1])
	}
	if errCount.Load() > 0 {
		os.Exit(1)
	}
}

// buildBulkRequest builds a Bulk request of opsPerRequest Create
// operations, each userName unique across the whole run (workerID and a
// per-worker monotonic counter), so concurrent workers never collide on
// the same name and repeated calls from the same worker never re-submit
// a name it already created.
func buildBulkRequest(workerID int, counter int64, opsPerRequest int) string {
	var b strings.Builder
	b.WriteString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[`)
	for i := range opsPerRequest {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"method":"POST","path":"/Users","data":{"userName":"scimload-w%d-c%d-o%d","active":true}}`, workerID, counter, i)
	}
	b.WriteString(`]}`)
	return b.String()
}

func post(url, bearerToken, body string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// allOperationsSucceeded reports whether every operation in a Bulk
// response reported a 2xx status -- the outer HTTP status is always 200
// for any well-formed Bulk request, per handleBulk, so a per-operation
// failure (e.g. an accidental userName collision) would otherwise be
// silently counted as a successful load-test iteration.
func allOperationsSucceeded(respBody []byte) bool {
	var parsed struct {
		Operations []struct {
			Status string `json:"status"`
		} `json:"Operations"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return false
	}
	if len(parsed.Operations) == 0 {
		return false
	}
	for _, op := range parsed.Operations {
		if len(op.Status) == 0 || op.Status[0] != '2' {
			return false
		}
	}
	return true
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
