package reload_test

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestWatchFiles_CallsFnOnWrite is the actual point of this feature: an
// operator editing a watched file on disk (a plain os.WriteFile, the
// simplest real save) triggers Fn without any HTTP call or restart.
func TestWatchFiles_CallsFnOnWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	stop := make(chan struct{})
	defer close(stop)

	if err := reload.WatchFiles(discardLogger(), []reload.WatchTarget{
		{Path: path, Name: "policy", Fn: func() error { calls.Add(1); return nil }},
	}, stop); err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}

	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 1 })
}

// TestWatchFiles_SurvivesAtomicRenameSave is the specific failure mode
// a naive "watch the file itself" implementation has: an editor that
// saves by writing a temp file and renaming it over the original
// (vim's default, and many editors/tools) orphans a watch on the old
// inode. WatchFiles watches the enclosing directory instead -- this
// proves that actually works, not just the plain os.WriteFile case
// above.
func TestWatchFiles_SurvivesAtomicRenameSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rbac.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	stop := make(chan struct{})
	defer close(stop)

	if err := reload.WatchFiles(discardLogger(), []reload.WatchTarget{
		{Path: path, Name: "rbac", Fn: func() error { calls.Add(1); return nil }},
	}, stop); err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 1 })
}

// TestWatchFiles_DebouncesBurstOfWrites proves a rapid burst of writes
// to the same file (the shape a single logical save often actually
// produces at the syscall level -- write, then a separate chmod/rename)
// collapses into ONE Fn call, not one per underlying event.
func TestWatchFiles_DebouncesBurstOfWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("v0"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	stop := make(chan struct{})
	defer close(stop)

	if err := reload.WatchFiles(discardLogger(), []reload.WatchTarget{
		{Path: path, Name: "config", Fn: func() error { calls.Add(1); return nil }},
	}, stop); err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("v"+string(rune('1'+i))), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // well under debounceWindow -- keeps this one burst
	}

	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 1 })
	// Give any over-eager duplicate call a chance to show up before
	// asserting there wasn't one.
	time.Sleep(500 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 debounced call for a burst of 5 rapid writes, got %d", got)
	}
}

// TestWatchFiles_SharedFileTriggersEveryTarget proves the config.yaml
// case: more than one WatchTarget naming the SAME Path (policy, rbac,
// and budget all backed by one config file) each get their own Fn
// called independently when that one file changes.
func TestWatchFiles_SharedFileTriggersEveryTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	fired := map[string]bool{}
	record := func(name string) func() error {
		return func() error {
			mu.Lock()
			fired[name] = true
			mu.Unlock()
			return nil
		}
	}

	stop := make(chan struct{})
	defer close(stop)

	if err := reload.WatchFiles(discardLogger(), []reload.WatchTarget{
		{Path: path, Name: "policy", Fn: record("policy")},
		{Path: path, Name: "rbac", Fn: record("rbac")},
		{Path: path, Name: "budget", Fn: record("budget")},
	}, stop); err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}

	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return fired["policy"] && fired["rbac"] && fired["budget"]
	})
}

// TestWatchFiles_FnErrorIsLoggedNotFatal proves a bad on-disk edit
// (Fn returning an error, e.g. a config that fails validation) doesn't
// crash the watcher goroutine -- a SUBSEQUENT valid edit still triggers
// a successful call.
func TestWatchFiles_FnErrorIsLoggedNotFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	var succeed atomic.Bool
	stop := make(chan struct{})
	defer close(stop)

	if err := reload.WatchFiles(discardLogger(), []reload.WatchTarget{
		{Path: path, Name: "policy", Fn: func() error {
			calls.Add(1)
			if !succeed.Load() {
				return errors.New("simulated bad config")
			}
			return nil
		}},
	}, stop); err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}

	if err := os.WriteFile(path, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 1 })

	succeed.Store(true)
	if err := os.WriteFile(path, []byte("good"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 2 })
}

// TestWatchFiles_EmptyTargetsIsNoop covers the "feature flag on but no
// watchable paths configured" edge case -- must not error or block.
func TestWatchFiles_EmptyTargetsIsNoop(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	if err := reload.WatchFiles(discardLogger(), nil, stop); err != nil {
		t.Fatalf("WatchFiles(nil): %v", err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
