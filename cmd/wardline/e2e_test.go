package main_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
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

	_ "github.com/jackc/pgx/v5/stdlib"
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

// cmdWaiter runs exec.Cmd.Wait exactly once in a background goroutine and
// makes its result available to any number of readers via a closed
// channel — exec.Cmd.Wait must not be called concurrently or more than
// once, so every caller that needs the exit result (cleanup, and any test
// that wants to observe a clean exit) reads from the same waiter instead
// of each calling Wait itself.
type cmdWaiter struct {
	done chan struct{}
	err  error
}

// waitFor starts cmd (already Start'ed) draining via a single Wait call.
func waitFor(cmd *exec.Cmd) *cmdWaiter {
	w := &cmdWaiter{done: make(chan struct{})}
	go func() {
		w.err = cmd.Wait()
		close(w.done)
	}()
	return w
}

// startWardline writes policyBody to policyFilename and a wardline.yaml
// (with extraConfigLines appended, e.g. "policy_backend: opa"), builds the
// wardline binary, and starts it as a subprocess pointed at a mock upstream
// that 200s on anything. It blocks until the server is ready and registers
// cleanup for the subprocess and upstream. Returns the address the server
// is listening on, the buffers capturing its stdout (the audit log
// defaults there) and stderr (for test failure diagnostics, or
// log-content assertions), the *exec.Cmd itself, and a cmdWaiter draining
// its exit — tests that care about the exit result (e.g. after sending
// SIGTERM) read from the waiter rather than calling cmd.Wait() themselves,
// since Wait must only ever be called once per process.
func startWardline(t *testing.T, policyFilename, policyBody, extraConfigLines string) (listenAddr string, stdout, stderr *safeBuffer, cmd *exec.Cmd, waiter *cmdWaiter) {
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

	// The default audit block below is only appended when extraConfigLines
	// doesn't already define one — a caller supplying its own "audit:"
	// section (e.g. to set postgres_dsn) would otherwise collide with this
	// one, and yaml.v3 hard-errors on duplicate top-level mapping keys
	// rather than letting the later one win.
	defaultAudit := "audit:\n  output: stdout\n"
	if strings.Contains(extraConfigLines, "audit:") {
		defaultAudit = ""
	}
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
%s
%s`, listenAddr, upstream.URL, policyPath, extraConfigLines, defaultAudit)), 0644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd = exec.Command(binPath, "serve", "--config", configPath)
	// Shorten the OTel SDK's default 5s batch-export interval so
	// tracing-enabled tests don't need to wait on it — faster and more
	// deterministic than racing a 10s polling deadline against a 5s batch
	// timer. Harmless for every other test: only tracing-enabled ones
	// touch batch export timing at all.
	cmd.Env = append(os.Environ(), "OTEL_BSP_SCHEDULE_DELAY=200")
	stdout = &safeBuffer{}
	stderr = &safeBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wardline: %v", err)
	}
	waiter = waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done // reading a closed channel never blocks, so this is safe even if the test already consumed waiter.done itself
	})

	waitForServer(t, "http://"+listenAddr)
	return listenAddr, stdout, stderr, cmd, waiter
}

func TestServeEndToEnd(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
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
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.rego", `package wardline.authz

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
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
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
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.rego", `package wardline.authz

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
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
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

	listenAddr, stdout, stderr, _, _ := startWardline(t, "policy.yaml", `
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
			assertAuditLogHasTraceID(t, stdout)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("collector never received a span export within the deadline (stderr: %s)", stderr.String())
}

// assertAuditLogHasTraceID parses the last non-empty line of the
// subprocess's stdout (the audit log defaults there) as a JSON audit
// entry and asserts its trace_id field is present and not an all-zero
// placeholder — proving the whole pipeline (config -> Provider -> Handler
// -> OTel SDK -> audit record) threads a real trace ID through, not just
// that some export happened.
func assertAuditLogHasTraceID(t *testing.T, stdout *safeBuffer) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	var lastLine string
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			lastLine = lines[i]
			break
		}
	}
	if lastLine == "" {
		t.Fatalf("no audit log line found in stdout: %q", stdout.String())
	}
	var entry struct {
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal([]byte(lastLine), &entry); err != nil {
		t.Fatalf("audit log line is not valid JSON: %v (line: %s)", err, lastLine)
	}
	if entry.TraceID == "" {
		t.Fatalf("expected a non-empty trace_id in the audit log line, got none (line: %s)", lastLine)
	}
	if entry.TraceID == "00000000000000000000000000000000" {
		t.Fatalf("expected a real trace_id, got an all-zeros placeholder: %s", entry.TraceID)
	}
}

// TestServeEndToEnd_DashboardServesWhenEnabled proves the web_ui feature
// flag, once on, actually mounts the dashboard in the real binary: the SPA
// shell is servable and its audit API reflects a real proxied call, not
// just that the handlers compile in isolation.
func TestServeEndToEnd_DashboardServesWhenEnabled(t *testing.T) {
	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-1"
    tool: "read_file"
    effect: allow
default: deny
`, "features:\n  web_ui: true\n")

	// Drive one call through the proxy so the dashboard has something to show.
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", "agent-1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call failed: %v; stderr=%s", err, stderr.String())
	}
	_ = resp.Body.Close()

	// The SPA shell loads.
	shellResp, err := http.Get("http://" + addr + "/dashboard/")
	if err != nil {
		t.Fatalf("dashboard root failed: %v", err)
	}
	defer func() { _ = shellResp.Body.Close() }()
	if shellResp.StatusCode != http.StatusOK {
		t.Errorf("dashboard root status = %d, want 200", shellResp.StatusCode)
	}
	shellBody, _ := io.ReadAll(shellResp.Body)
	if !strings.Contains(string(shellBody), `id="app"`) {
		t.Errorf("dashboard root body missing SPA shell marker: %s", shellBody)
	}

	// The audit API reflects the call made above.
	auditResp, err := http.Get("http://" + addr + "/dashboard/api/audit?after=0&limit=10")
	if err != nil {
		t.Fatalf("dashboard audit API failed: %v", err)
	}
	defer func() { _ = auditResp.Body.Close() }()
	var entries []struct {
		Identity string
		Tool     string
		Decision string
	}
	if err := json.NewDecoder(auditResp.Body).Decode(&entries); err != nil {
		t.Fatalf("invalid audit JSON: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Identity == "agent-1" && e.Tool == "read_file" && e.Decision == "allow" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the proxied call to appear in the dashboard's audit feed, got %+v", entries)
	}
}

// TestServeEndToEnd_DashboardNotMountedWhenDisabled proves the web_ui flag
// actually gates mux registration (not just something inert in the config
// layer): with the flag off, /dashboard/ falls through to the same proxy
// path as any other unmatched URL. An unmatched GET carries no JSON-RPC
// body, so ParseRequest rejects it and the proxy handler returns 400 —
// asserting that status directly (rather than only conditionally inspecting
// a 200 body) fails loudly both if the dashboard ever got erroneously
// mounted (200 + `id="app"`) and if the proxy's own unmatched-path
// behavior silently changed.
func TestServeEndToEnd_DashboardNotMountedWhenDisabled(t *testing.T) {
	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-1"
    tool: "read_file"
    effect: allow
default: deny
`, "")

	resp, err := http.Get("http://" + addr + "/dashboard/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 (unmatched path routed to the proxy, which rejects the bodyless GET) when web_ui is off, got %d (stderr: %s, body: %s)", resp.StatusCode, stderr.String(), body)
	}
	if strings.Contains(string(body), `id="app"`) {
		t.Error("dashboard SPA should not be reachable when web_ui is off")
	}
}

// TestServeEndToEnd_GracefulShutdown proves SIGTERM drains the server and
// exits cleanly within the shutdown timeout, rather than hanging or
// needing a force-kill — the path a batched OTLP exporter's final flush
// depends on.
func TestServeEndToEnd_GracefulShutdown(t *testing.T) {
	_, _, stderr, cmd, waiter := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, "")

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	// Read the same waiter startWardline's cleanup will later read from,
	// rather than calling cmd.Wait() ourselves — exec.Cmd.Wait must not be
	// called concurrently or more than once per process, and cleanup's
	// <-waiter.done races with a second, independent Wait() call if the
	// test's own 15s timeout fires while cleanup is also unwinding.
	select {
	case <-waiter.done:
		if waiter.err != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got: %v (stderr: %s)", waiter.err, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("process did not exit within 15s of SIGTERM (stderr: %s)", stderr.String())
	}
}

// TestServeEndToEnd_PostgresStorage proves the postgres_storage feature
// flag, once on, actually writes audit entries to a real Postgres database
// through the real binary — not just that PostgresWriter's adapter tests
// pass in isolation. Requires WARDLINE_TEST_POSTGRES_DSN pointing at a real
// Postgres instance; skips otherwise, matching this repo's other
// real-dependency-gated tests (see internal/features/audit/adapter's own
// Docker-gated Postgres tests).
func TestServeEndToEnd_PostgresStorage(t *testing.T) {
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres e2e test")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db for cleanup/verification: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_entries`); err != nil {
		t.Fatalf("drop table before test: %v", err)
	}

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-1"
    tool: "read_file"
    effect: allow
default: deny
`, "features:\n  postgres_storage: true\naudit:\n  postgres_dsn: \""+dsn+"\"\n")

	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", "agent-1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call failed: %v; stderr=%s", err, stderr.String())
	}
	_ = resp.Body.Close()

	var identity, tool, decision string
	// The audit write happens after the response is sent (ModifyResponse
	// callback) — poll briefly rather than assuming it's landed
	// instantly, matching this file's existing polling patterns for
	// other async-after-response effects.
	// Filter by identity/tool rather than a bare LIMIT 1: the server's own
	// readiness probe in startWardline (a bodyless GET) also lands a row
	// here first, with decision "error" and empty identity/tool, since
	// audit recording covers unparseable requests too.
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = db.QueryRow(`SELECT identity, tool, decision FROM audit_entries WHERE identity = $1 AND tool = $2 ORDER BY id DESC LIMIT 1`, "agent-1", "read_file").Scan(&identity, &tool, &decision)
		if lastErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("audit entry never appeared in postgres: %v", lastErr)
	}
	if identity != "agent-1" || tool != "read_file" || decision != "allow" {
		t.Errorf("unexpected audit row: identity=%s tool=%s decision=%s", identity, tool, decision)
	}
}
