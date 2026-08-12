// Command sessionload drives concurrent, per-session stateful call
// sequences at a running wardline serve -- taint_tracking and
// approval_workflow both gate a WRITE based on state a prior READ (or
// operator approval) set for that exact session, so a flat repeatable
// vegeta body can't express either: unlike a rate/budget ceiling, this
// is "session N's own history", checked with many concurrent, isolated
// sessions to prove no cross-session leakage under real concurrency
// (not just correctness in a single sequential session, which the e2e
// tests at cmd/wardline/e2e_taint_test.go and e2e_approval_test.go
// already cover).
//
// Usage:
//
//	sessionload taint <wardline-addr> <identity> <concurrency> <iterations-per-session>
//	sessionload approval <wardline-addr> <identity> <concurrency> <iterations-per-session>
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var httpClient = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

func main() {
	if len(os.Args) != 6 {
		usage()
	}
	mode, addr, identity := os.Args[1], os.Args[2], os.Args[3]
	concurrency, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad concurrency:", err)
		os.Exit(2)
	}
	iterations, err := strconv.Atoi(os.Args[5])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad iterations:", err)
		os.Exit(2)
	}

	var run func(addr, identity, session string, iterations int) (ok, failed int64)
	switch mode {
	case "taint":
		run = runTaintSession
	case "approval":
		run = runApprovalSession
	default:
		usage()
	}

	var totalOK, totalFailed atomic.Int64
	var wg sync.WaitGroup
	for w := range concurrency {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			session := fmt.Sprintf("sessionload-%s-%d", mode, workerID)
			ok, failed := run(addr, identity, session, iterations)
			totalOK.Add(ok)
			totalFailed.Add(failed)
		}(w)
	}
	wg.Wait()

	fmt.Printf("%s: %d concurrent sessions x %d iterations -- %d correct, %d WRONG\n", mode, concurrency, iterations, totalOK.Load(), totalFailed.Load())
	if totalFailed.Load() > 0 {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sessionload taint|approval <wardline-addr> <identity> <concurrency> <iterations-per-session>")
	os.Exit(2)
}

// runTaintSession repeats, iterations times, the sequence
// TestServeEndToEnd_TaintHonorsSessionHeader proves once sequentially:
// an untrusted read (web_fetch) taints THIS session, so the very next
// write (delete_file) on the SAME session must be denied. Every
// worker's session string is unique (main's session naming), so a
// failure here means real cross-session leakage under concurrency, not
// a naming collision.
func runTaintSession(addr, identity, session string, iterations int) (ok, failed int64) {
	for range iterations {
		readStatus := call(addr, identity, session, "web_fetch")
		if readStatus != http.StatusOK {
			failed++
			continue
		}
		writeStatus := call(addr, identity, session, "delete_file")
		if writeStatus != http.StatusForbidden {
			failed++
			continue
		}
		ok++
	}
	return ok, failed
}

// runApprovalSession repeats, iterations times, the full sequence
// TestServeEndToEnd_ApprovalGrantsAfterApprove proves once sequentially:
// read taints -> write is held (202) -> operator approves this exact
// session's pending request (matched by the Session field, not "the
// first pending", since many concurrent sessions have their own pending
// entries at once) -> the grant admits exactly one retry (200) -> the
// call after that is held again (202, single-use consumed).
func runApprovalSession(addr, identity, session string, iterations int) (ok, failed int64) {
	for range iterations {
		if call(addr, identity, session, "web_fetch") != http.StatusOK {
			failed++
			continue
		}
		if call(addr, identity, session, "delete_file") != http.StatusAccepted {
			failed++
			continue
		}
		id, err := findPendingBySession(addr, session)
		if err != nil {
			failed++
			continue
		}
		if !approve(addr, id) {
			failed++
			continue
		}
		if call(addr, identity, session, "delete_file") != http.StatusOK {
			failed++
			continue
		}
		if call(addr, identity, session, "delete_file") != http.StatusAccepted {
			failed++
			continue
		}
		ok++
	}
	return ok, failed
}

func call(addr, identity, session, tool string) int {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q}}`, tool)
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("X-Wardline-Identity", identity)
	req.Header.Set("X-Wardline-Session", session)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

type pendingRequest struct {
	ID      string
	Session string
}

// findPendingBySession lists every pending approval (the operator
// surface has no per-session filter) and returns the one matching
// session -- required because, under concurrency, many other sessions'
// own pending requests are listed alongside this one.
func findPendingBySession(addr, session string) (string, error) {
	resp, err := httpClient.Get("http://" + addr + "/approvals/pending")
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var pending []pendingRequest
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		return "", err
	}
	for _, p := range pending {
		if p.Session == session {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("no pending approval found for session %q", session)
}

func approve(addr, id string) bool {
	resp, err := httpClient.Post("http://"+addr+"/approvals/"+id+"/approve", "application/json", nil)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusNoContent
}
