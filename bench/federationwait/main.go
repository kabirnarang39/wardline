// Command federationwait polls a running wardline instance's
// /dashboard/api/federation/correlated until a CorrelatedAlert naming
// every wanted instance ID appears, or a deadline elapses. Factored out
// of bench/run.sh (a bare shell script has no good JSON-array-of-strings
// containment check) rather than reimplemented as fragile jq/grep
// pipeline -- mirrors cmd/wardline/e2e_test.go's own
// waitForCorrelatedAlertE2E, just against a real bench-launched instance
// instead of a test subprocess.
//
// Usage: federationwait <addr> <deadline> <wanted-instance-id-1> [wanted-instance-id-2 ...]
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type correlatedAlert struct {
	InstanceIDs []string `json:"instance_ids"`
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: federationwait <addr> <deadline> <wanted-instance-id-1> [wanted-instance-id-2 ...]")
		os.Exit(2)
	}
	addr := os.Args[1]
	deadlineDur, err := time.ParseDuration(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad deadline:", err)
		os.Exit(2)
	}
	wanted := os.Args[3:]

	deadline := time.Now().Add(deadlineDur)
	for time.Now().Before(deadline) {
		if found(addr, wanted) {
			fmt.Printf("CORRELATED: found an alert covering %v at %s\n", wanted, addr)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Printf("NOT CORRELATED: no alert covering %v appeared at %s within %s\n", wanted, addr, deadlineDur)
	os.Exit(1)
}

func found(addr string, wanted []string) bool {
	resp, err := http.Get("http://" + addr + "/dashboard/api/federation/correlated?after=0&limit=50")
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var alerts []correlatedAlert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return false
	}
	for _, a := range alerts {
		seen := make(map[string]bool, len(a.InstanceIDs))
		for _, id := range a.InstanceIDs {
			seen[id] = true
		}
		allPresent := true
		for _, w := range wanted {
			if !seen[w] {
				allPresent = false
				break
			}
		}
		if allPresent {
			return true
		}
	}
	return false
}
