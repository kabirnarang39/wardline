package main_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// safeBuffer is a mutex-guarded bytes.Buffer. The subprocess's stderr is
// forwarded to it by an internal exec.Cmd goroutine while the process is
// running; tests read it via String() both on failure and (for log-content
// assertions) while the process is still alive — a plain bytes.Buffer would
// race between that writer and these readers.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// startWardline writes policyBody to policyFilename and a wardline.yaml
// (with extraConfigLines appended, e.g. "policy_backend: opa"), builds the
// wardline binary, and starts it as a subprocess pointed at a mock upstream
// that 200s on anything. It blocks until the server is ready and registers
// cleanup for the subprocess and upstream. Returns the address the server
// is listening on and the buffer capturing its stderr (for test failure
// diagnostics, or log-content assertions).
func startWardline(t *testing.T, policyFilename, policyBody, extraConfigLines string) (listenAddr string, stderr *safeBuffer, cmd *exec.Cmd) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, policyFilename)
	configPath := filepath.Join(dir, "wardline.yaml")
	listenAddr = reserveAddr(t)

	if err := os.WriteFile(policyPath, []byte(policyBody), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
%s
audit:
  output: stdout
`, listenAddr, upstream.URL, policyPath, extraConfigLines)), 0644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd = exec.Command(binPath, "serve", "--config", configPath)
	stderr = &safeBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wardline: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	waitForServer(t, "http://"+listenAddr)
	return listenAddr, stderr, cmd
}

func TestServeEndToEnd(t *testing.T) {
	listenAddr, stderr, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, "")

	allowResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for allowed call, got %d (stderr: %s)", allowResp.StatusCode, stderr.String())
	}

	denyResp := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for denied call, got %d (stderr: %s)", denyResp.StatusCode, stderr.String())
	}
}

// reserveAddr binds an ephemeral port to find one that's free, then closes
// the listener immediately so the wardline subprocess can bind it. This
// avoids hardcoding a port that could collide under parallel/shared CI runs.
func reserveAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(addr); err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready", addr)
}

func postToolCall(t *testing.T, listenAddr, identity, tool string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q}}`, tool)
	return postToolCallBody(t, listenAddr, identity, body)
}

// postToolCallWithPath is like postToolCall but adds an
// "arguments":{"path":...} object to params, for policies that branch on
// tool arguments rather than just identity/tool.
func postToolCallWithPath(t *testing.T, listenAddr, identity, tool, path string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q,"arguments":{"path":%q}}}`, tool, path)
	return postToolCallBody(t, listenAddr, identity, body)
}

func postToolCallBody(t *testing.T, listenAddr, identity, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	return resp
}

// TestServeEndToEnd_OPABackend proves the richer policy.Context (params,
// not just identity/tool) survives a real HTTP request end-to-end through
// the OPA backend — a policy expressible with the YAML backend wouldn't
// prove that.
func TestServeEndToEnd_OPABackend(t *testing.T) {
	listenAddr, stderr, _ := startWardline(t, "policy.rego", `package wardline.authz

default allow = false

allow {
	input.identity == "agent-abc123"
	input.tool == "read_file"
	startswith(input.params.arguments.path, "/safe/")
}
`, "policy_backend: opa")

	allowResp := postToolCallWithPath(t, listenAddr, "agent-abc123", "read_file", "/safe/x")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a /safe/ path, got %d (stderr: %s)", allowResp.StatusCode, stderr.String())
	}

	unsafePathResp := postToolCallWithPath(t, listenAddr, "agent-abc123", "read_file", "/unsafe/x")
	if unsafePathResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a /unsafe/ path, got %d (stderr: %s)", unsafePathResp.StatusCode, stderr.String())
	}

	denyResp := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for denied call, got %d (stderr: %s)", denyResp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_BudgetThrottles proves budget enforcement works over a
// real HTTP request through the real binary, using the real wall clock (not
// an injected one, unlike the unit-level limiter tests): a
// requests_per_window of 1 means the second allowed call in the same window
// gets throttled, not forwarded — and a third call after the (short,
// window_seconds: 1) window has rolled over succeeds again, proving the
// fixed-window reset through config-parsing/time.Now(), not just the bare
// limiter with an injected clock.
func TestServeEndToEnd_BudgetThrottles(t *testing.T) {
	listenAddr, stderr, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, `features:
  budget_enforcement: true
budget:
  requests_per_window: 1
  window_seconds: 1`)

	firstResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the first call within budget, got %d (stderr: %s)", firstResp.StatusCode, stderr.String())
	}

	secondResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if secondResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for the second call in the same window, got %d (stderr: %s)", secondResp.StatusCode, stderr.String())
	}

	time.Sleep(1200 * time.Millisecond) // past the 1s window
	thirdResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if thirdResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a call in the next window, got %d (stderr: %s)", thirdResp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_OPABackendWithBudget proves the OPA policy backend and
// budget enforcement compose correctly through the real binary — only the
// YAML backend was previously exercised with a budget, leaving the
// combination assumed-safe by code inspection rather than tested.
func TestServeEndToEnd_OPABackendWithBudget(t *testing.T) {
	listenAddr, stderr, _ := startWardline(t, "policy.rego", `package wardline.authz

default allow = false

allow {
	input.identity == "agent-abc123"
	input.tool == "read_file"
}
`, `policy_backend: opa
features:
  budget_enforcement: true
budget:
  requests_per_window: 1
  window_seconds: 60`)

	firstResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the first OPA-allowed call within budget, got %d (stderr: %s)", firstResp.StatusCode, stderr.String())
	}

	secondResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if secondResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for the second OPA-allowed call in the same window, got %d (stderr: %s)", secondResp.StatusCode, stderr.String())
	}

	denyResp := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for an OPA-denied call (budget never consulted), got %d (stderr: %s)", denyResp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_BudgetConfiguredButFlagOffWarns proves an operator who
// sets a budget block but forgets to flip features.budget_enforcement gets
// a log signal instead of silent no-op enforcement, and that enforcement is
// in fact not applied (the call succeeds despite requests_per_window: 1).
func TestServeEndToEnd_BudgetConfiguredButFlagOffWarns(t *testing.T) {
	listenAddr, stderr, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, `budget:
  requests_per_window: 1
  window_seconds: 60`)

	firstResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the first call, got %d (stderr: %s)", firstResp.StatusCode, stderr.String())
	}
	secondResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if secondResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the second call too (budget_enforcement flag is off), got %d (stderr: %s)", secondResp.StatusCode, stderr.String())
	}

	if !strings.Contains(stderr.String(), "budget config is set but features.budget_enforcement is off") {
		t.Errorf("expected a warning log about unenforced budget config, got stderr: %s", stderr.String())
	}
}

// TestServeEndToEnd_OTLPExport proves the whole tracing pipeline fires for
// real: config -> Provider -> Handler -> OTel SDK batching -> network
// export, not just unit-tested in isolation. The fake collector only
// records whether any POST arrived — decoding the OTLP protobuf wire
// format is more machinery than this test needs.
func TestServeEndToEnd_OTLPExport(t *testing.T) {
	var gotExport atomic.Bool
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExport.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	// collector.URL is "http://127.0.0.1:PORT" — otlptracehttp.WithEndpoint
	// wants host:port, no scheme.
	collectorHostPort := strings.TrimPrefix(collector.URL, "http://")

	listenAddr, stderr, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  otel_tracing: true
tracing:
  otlp_endpoint: "%s"`, collectorHostPort))

	resp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if gotExport.Load() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("collector never received a span export within the deadline (stderr: %s)", stderr.String())
}

// TestServeEndToEnd_GracefulShutdown proves SIGTERM drains the server and
// exits cleanly within the shutdown timeout, rather than hanging or
// needing a force-kill — the path a batched OTLP exporter's final flush
// depends on.
func TestServeEndToEnd_GracefulShutdown(t *testing.T) {
	_, stderr, cmd := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, "")

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("process did not exit within 15s of SIGTERM (stderr: %s)", stderr.String())
	}
}
