package main_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	// rather than letting the later one win. Checked as a line-anchored
	// prefix/line match rather than a bare substring, so a hypothetical
	// future caller passing something like "# audit: see below" in a
	// comment doesn't falsely suppress the default block.
	defaultAudit := "audit:\n  output: stdout\n"
	if strings.HasPrefix(extraConfigLines, "audit:") || strings.Contains(extraConfigLines, "\naudit:") {
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
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(addr); err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready", addr)
}

// waitForListener waits for a TCP listener at addr to accept connections,
// without sending any request through it. Unlike waitForServer, this
// never reaches wardline's proxy/audit path, so it's safe to use in tests
// that assert exact audit-entry counts against the same server.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
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
//
// WARNING: this test DROPs the audit_entries table at whatever DSN
// WARDLINE_TEST_POSTGRES_DSN points at. Point this at a disposable
// database only — never at a real/shared one.
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
	// The audit write happens synchronously on the request path (in
	// ModifyResponse, before the response is written back to the client),
	// but poll briefly anyway rather than assuming this test's own SELECT
	// races the INSERT's transaction commit, matching this file's existing
	// polling patterns elsewhere.
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

// postCredentialsToken calls POST /credentials/token directly (not
// through postToolCall, which always sets X-Wardline-Identity — the
// header this feature's bearer-mode intentionally stops trusting).
func postCredentialsToken(t *testing.T, listenAddr, secret string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"secret":%q}`, secret)
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/credentials/token", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postToolCallWithBearer(t *testing.T, listenAddr, bearerToken, tool string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q}}`, tool)
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	return resp
}

// TestServeEndToEnd_CredentialIssuance proves the full bootstrap → bearer
// tool-call → revoke → rejected flow over a real HTTP request through the
// real binary, and that every rejection path fails closed with 401,
// including the specific regression this feature exists to prevent: a
// raw X-Wardline-Identity header alone, with no bearer token, must be
// rejected once the flag is on.
func TestServeEndToEnd_CredentialIssuance(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: agent-abc123
    secret: "a-long-random-registration-secret"
`), 0644); err != nil {
		t.Fatal(err)
	}

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  credential_issuance: true
credential:
  identities_file: "%s"`, credentialsPath))

	// Wrong secret is rejected, no token issued.
	badResp := postCredentialsToken(t, listenAddr, "wrong-secret")
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a wrong secret, got %d (stderr: %s)", badResp.StatusCode, stderr.String())
	}

	// Bootstrap a real token.
	tokenResp := postCredentialsToken(t, listenAddr, "a-long-random-registration-secret")
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping a valid secret, got %d (stderr: %s)", tokenResp.StatusCode, stderr.String())
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	_ = tokenResp.Body.Close()
	if tokenBody.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	// The bearer token proxies a real allowed tool call.
	allowedResp := postToolCallWithBearer(t, listenAddr, tokenBody.Token, "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for an allowed call with a valid bearer token, got %d (stderr: %s)", allowedResp.StatusCode, stderr.String())
	}

	// No Authorization header at all is rejected.
	noAuthResp := postToolCallWithBearer(t, listenAddr, "", "read_file")
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no Authorization header, got %d", noAuthResp.StatusCode)
	}

	// A tampered token is rejected. Flip the first character of the
	// signature segment (not the last character of the whole token): a
	// base64url group carrying a partial byte has decode-don't-care bit
	// positions in its last character, so mutating there can (~45% of the
	// time, reproduced empirically) decode to the identical signature
	// bytes and pass verification by accident. The first character of a
	// full base64 group has no such collision — see the same fix in
	// internal/features/credential/adapter/jwt_test.go.
	parts := strings.SplitN(tokenBody.Token, ".", 3)
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("expected a 3-segment JWT, got %d segments", len(parts))
	}
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tamperedToken := parts[0] + "." + parts[1] + "." + string(sig)
	tamperedResp := postToolCallWithBearer(t, listenAddr, tamperedToken, "read_file")
	if tamperedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a tampered token, got %d", tamperedResp.StatusCode)
	}

	// The specific regression this feature exists to prevent: a raw
	// X-Wardline-Identity header alone, no bearer token, must not work.
	legacyHeaderResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if legacyHeaderResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a raw X-Wardline-Identity header with credential_issuance on, got %d", legacyHeaderResp.StatusCode)
	}

	// Revoke from loopback, then confirm the same token is rejected.
	revokeReq, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/credentials/revoke", bytes.NewBufferString(`{"identity":"agent-abc123"}`))
	if err != nil {
		t.Fatal(err)
	}
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatal(err)
	}
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 revoking from loopback, got %d (stderr: %s)", revokeResp.StatusCode, stderr.String())
	}

	revokedResp := postToolCallWithBearer(t, listenAddr, tokenBody.Token, "read_file")
	if revokedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a revoked identity's still-otherwise-valid token, got %d", revokedResp.StatusCode)
	}
}

// TestServeEndToEnd_AllFeaturesCombined is the v0.5 roadmap's final
// comprehensive check: every optional feature this project has built
// (OPA policy backend, budget enforcement, OTel tracing, the dashboard,
// Postgres storage) turned on simultaneously in one process, proving they
// compose correctly rather than only having been proven pairwise or in
// isolation by earlier, narrower e2e tests. Exercises the full request
// lifecycle — allow, throttle, deny — and confirms every sink (the
// Postgres-backed audit Writer, the dashboard's independent in-memory
// LiveSink, and the OTLP trace exporter) all receive the same events from
// the same Recorder.Record call, not just that each works when the others
// are off.
func TestServeEndToEnd_AllFeaturesCombined(t *testing.T) {
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping combined-features e2e test")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db for cleanup/verification: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_entries`); err != nil {
		t.Fatalf("drop table before test: %v", err)
	}

	var gotExport atomic.Bool
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExport.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	collectorHostPort := strings.TrimPrefix(collector.URL, "http://")

	addr, _, stderr, _, _ := startWardline(t, "policy.rego", `package wardline.authz

default allow = false

allow {
	input.identity == "agent-combo"
	input.tool == "read_file"
}
`, fmt.Sprintf(`policy_backend: opa
features:
  budget_enforcement: true
  otel_tracing: true
  web_ui: true
  postgres_storage: true
budget:
  requests_per_window: 1
  window_seconds: 60
tracing:
  otlp_endpoint: "%s"
audit:
  postgres_dsn: "%s"
`, collectorHostPort, dsn))

	// 1. First allowed call — consumes the identity's entire budget window.
	allowResp := postToolCall(t, addr, "agent-combo", "read_file")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the first OPA-allowed call within budget, got %d (stderr: %s)", allowResp.StatusCode, stderr.String())
	}
	_ = allowResp.Body.Close()

	// 2. Second allowed call in the same window — budget throttles it.
	throttledResp := postToolCall(t, addr, "agent-combo", "read_file")
	if throttledResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for the second call in the same budget window, got %d (stderr: %s)", throttledResp.StatusCode, stderr.String())
	}
	_ = throttledResp.Body.Close()

	// 3. A call OPA denies outright — budget never consulted for it.
	denyResp := postToolCall(t, addr, "agent-combo", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for an OPA-denied call, got %d (stderr: %s)", denyResp.StatusCode, stderr.String())
	}
	_ = denyResp.Body.Close()

	// The OTLP collector received at least one span export.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !gotExport.Load() {
		time.Sleep(100 * time.Millisecond)
	}
	if !gotExport.Load() {
		t.Fatalf("OTLP collector never received a span export within the deadline (stderr: %s)", stderr.String())
	}

	// All three decisions landed in Postgres, not just the allow path —
	// proving the Postgres writer is truly wired for the whole request
	// lifecycle, not only the happy path.
	wantDecisions := map[string]bool{"allow": false, "throttled": false, "deny": false}
	rows, err := db.Query(`SELECT decision FROM audit_entries WHERE identity = $1`, "agent-combo")
	if err != nil {
		t.Fatalf("query postgres audit entries: %v", err)
	}
	func() {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var decision string
			if err := rows.Scan(&decision); err != nil {
				t.Fatalf("scan postgres row: %v", err)
			}
			if _, ok := wantDecisions[decision]; ok {
				wantDecisions[decision] = true
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate postgres rows: %v", err)
		}
	}()
	for decision, seen := range wantDecisions {
		if !seen {
			t.Errorf("expected a %q decision in postgres audit_entries for agent-combo, never saw one", decision)
		}
	}

	// The dashboard's independent in-memory LiveSink also received the
	// same events — proving Recorder.Record fans out to both sinks
	// correctly when postgres_storage and web_ui are both on at once,
	// not just when tested individually.
	dashResp, err := http.Get("http://" + addr + "/dashboard/api/audit?after=0&limit=20")
	if err != nil {
		t.Fatalf("dashboard audit API failed: %v", err)
	}
	defer func() { _ = dashResp.Body.Close() }()
	var entries []struct {
		Identity string
		Tool     string
		Decision string
		TraceID  string
	}
	if err := json.NewDecoder(dashResp.Body).Decode(&entries); err != nil {
		t.Fatalf("invalid dashboard audit JSON: %v", err)
	}
	dashSeen := map[string]bool{"allow": false, "throttled": false, "deny": false}
	var sawTraceID bool
	for _, e := range entries {
		if e.Identity != "agent-combo" {
			continue
		}
		if _, ok := dashSeen[e.Decision]; ok {
			dashSeen[e.Decision] = true
		}
		if e.TraceID != "" {
			sawTraceID = true
		}
	}
	for decision, seen := range dashSeen {
		if !seen {
			t.Errorf("expected a %q decision in the dashboard's live audit feed for agent-combo, never saw one", decision)
		}
	}
	if !sawTraceID {
		t.Error("expected at least one dashboard audit entry to carry a non-empty trace_id (otel_tracing is on)")
	}

	// The dashboard SPA itself is reachable — the whole web_ui path is up,
	// not just its JSON API.
	shellResp, err := http.Get("http://" + addr + "/dashboard/")
	if err != nil {
		t.Fatalf("dashboard root failed: %v", err)
	}
	defer func() { _ = shellResp.Body.Close() }()
	shellBody, _ := io.ReadAll(shellResp.Body)
	if !strings.Contains(string(shellBody), `id="app"`) {
		t.Errorf("dashboard root body missing SPA shell marker: %s", shellBody)
	}
}

// TestServeEndToEnd_RBACDashboard proves rbac gates the dashboard over a
// real HTTP request through the real binary: an identity with no
// binding gets 403, an identity bound to "viewer" gets in.
func TestServeEndToEnd_RBACDashboard(t *testing.T) {
	dir := t.TempDir()
	rbacPath := filepath.Join(dir, "rbac.yaml")
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: alice
    role: viewer
`), 0644); err != nil {
		t.Fatal(err)
	}

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "alice"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  web_ui: true
  rbac: true
rbac:
  config_file: "%s"`, rbacPath))

	// alice, bound to viewer, reaches the dashboard.
	req, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice (bound viewer), got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}

	// bob, unbound, is forbidden.
	req2, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("X-Wardline-Identity", "bob")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for bob (unbound), got %d", resp2.StatusCode)
	}
}

// TestServeEndToEnd_RBACWithCredentialIssuance proves rbac's dashboard
// middleware genuinely resolves identity through credential_issuance's
// bearer/JWT IdentityAuthenticator (bearerIdentity) when both flags are on
// — not just through the raw X-Wardline-Identity header, which
// credential_issuance stops trusting entirely (see
// TestServeEndToEnd_CredentialIssuance). A real bootstrapped token for
// alice, bound to "viewer" in rbac.yaml, must authorize the dashboard; a
// missing/invalid Authorization header must be rejected with 401 by the
// same middleware, proving a failed bearer resolution doesn't silently
// fall back to the header.
func TestServeEndToEnd_RBACWithCredentialIssuance(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: alice
    secret: "a-long-random-registration-secret"
`), 0644); err != nil {
		t.Fatal(err)
	}
	rbacPath := filepath.Join(dir, "rbac.yaml")
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: alice
    role: viewer
`), 0644); err != nil {
		t.Fatal(err)
	}

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "alice"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  web_ui: true
  credential_issuance: true
  rbac: true
credential:
  identities_file: "%s"
rbac:
  config_file: "%s"`, credentialsPath, rbacPath))

	// Bootstrap a real bearer token for alice.
	tokenResp := postCredentialsToken(t, listenAddr, "a-long-random-registration-secret")
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping a valid secret, got %d (stderr: %s)", tokenResp.StatusCode, stderr.String())
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	_ = tokenResp.Body.Close()
	if tokenBody.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	// The bearer token, resolved through bearerIdentity (not
	// X-Wardline-Identity), authorizes the dashboard via alice's viewer
	// binding.
	req, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenBody.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice's bearer token (bound viewer), got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}

	// A missing/invalid Authorization header fails identity resolution and
	// is rejected outright — it must not silently fall back to
	// X-Wardline-Identity.
	req2, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no Authorization header, got %d", resp2.StatusCode)
	}
}

// TestServeEndToEnd_CedarBackend proves the richer policy.Context (params,
// not just identity/tool) survives a real HTTP request end-to-end through
// the Cedar backend — a policy expressible with the YAML backend wouldn't
// prove that.
func TestServeEndToEnd_CedarBackend(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.cedar", `
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
) when {
  context.params.arguments.path like "/safe/*"
};
`, "policy_backend: cedar")

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

// TestServeEndToEnd_AnomalyDetectionRateSpike proves a real burst of
// calls from one identity produces a JSONL anomaly line and shows up via
// /dashboard/api/anomalies, through the real binary end to end.
func TestServeEndToEnd_AnomalyDetectionRateSpike(t *testing.T) {
	dir := t.TempDir()
	anomalyPath := filepath.Join(dir, "anomaly.jsonl")

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
default: allow
`, fmt.Sprintf(`features:
  web_ui: true
  anomaly_detection: true
anomaly:
  output: "%s"
  window_seconds: 3
  rate_spike:
    enabled: true
    rate_multiplier: 2.0
    min_calls: 5`, anomalyPath))

	doCall := func(identity string) {
		resp := postToolCall(t, listenAddr, identity, "read_file")
		_ = resp.Body.Close()
	}

	// Baseline window: 5 calls. window_seconds is 3, not 1, purely for
	// timing headroom: the burst below has to land inside a single window,
	// and 11 sequential HTTP round-trips against a loaded CI runner can
	// take longer than a 1s window, which would split the burst across two
	// windows and silently stop it from ever exceeding the multiplier.
	for i := 0; i < 5; i++ {
		doCall("alice")
	}
	time.Sleep(3100 * time.Millisecond) // let the 3s window roll over
	// Next window: 11 calls -- above both 5*2.0=10 and the min-calls floor.
	for i := 0; i < 11; i++ {
		doCall("alice")
	}
	// The whole path (Recorder -> MultiSink -> Detector -> JSONLWriter) is
	// synchronous under the 11th request, so the anomaly line is already
	// on disk by the time that request's response returns -- no sleep or
	// polling needed here.

	data, err := os.ReadFile(anomalyPath)
	if err != nil {
		t.Fatalf("failed to read anomaly output: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Contains(data, []byte(`"kind":"rate_spike"`)) {
		t.Fatalf("expected a rate_spike anomaly line in %s, got: %s", anomalyPath, data)
	}

	resp, err := http.Get("http://" + listenAddr + "/dashboard/api/anomalies")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /dashboard/api/anomalies, got %d", resp.StatusCode)
	}
	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	found := false
	for _, e := range entries {
		if e["kind"] == "rate_spike" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a rate_spike entry via /dashboard/api/anomalies, got %+v", entries)
	}
}

// TestServeEndToEnd_AnomalyDetectionOffProducesNoOutput proves the
// parent flag off means zero anomaly behavior, even under the same
// burst that triggers a flag-on detection above. web_ui stays on (so the
// dashboard route itself is mounted, isolating what this test targets)
// while anomaly_detection is off, exercising the handler's documented
// nil-AnomalySource posture (see the NewHandler doc comment in
// internal/features/dashboard/adapter/handler.go: "anomalies may be nil
// ... /dashboard/api/anomalies then answers 404") rather than the
// unrelated "dashboard not mounted at all" case already covered by
// TestServeEndToEnd_DashboardNotMountedWhenDisabled.
func TestServeEndToEnd_AnomalyDetectionOffProducesNoOutput(t *testing.T) {
	listenAddr, _, _, _, _ := startWardline(t, "policy.yaml", `
default: allow
`, "features:\n  web_ui: true\n")

	for i := 0; i < 20; i++ {
		callResp := postToolCall(t, listenAddr, "alice", "read_file")
		_ = callResp.Body.Close()
	}

	resp, err := http.Get("http://" + listenAddr + "/dashboard/api/anomalies")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 from /dashboard/api/anomalies when anomaly_detection is off (web_ui on), got %d", resp.StatusCode)
	}
}

// TestValidateConfigEndToEnd_AnomalyOutputNotCreated proves
// `wardline validate-config` has no filesystem side effects: it must
// report a valid anomaly block without creating anomaly.output, which an
// earlier version did (O_CREATE on the real writer path) and which left a
// stray empty file behind on every validation run.
func TestValidateConfigEndToEnd_AnomalyOutputNotCreated(t *testing.T) {
	dir := t.TempDir()
	anomalyPath := filepath.Join(dir, "anomaly.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`listen: ":8080"
upstream: "http://localhost:9000"
policy_file: %q
audit:
  output: stdout
features:
  anomaly_detection: true
anomaly:
  output: %q
  window_seconds: 60
`, policyPath, anomalyPath)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	out, err := exec.Command(binPath, "validate-config", "--config", configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("validate-config failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("config file is valid")) {
		t.Fatalf("expected a valid verdict, got: %s", out)
	}
	if _, err := os.Stat(anomalyPath); !os.IsNotExist(err) {
		t.Fatalf("validate-config must not create anomaly.output (%s), stat err = %v", anomalyPath, err)
	}
}

// A bad anomaly.output directory is the one anomaly-output failure
// validate-config still has to catch, since the operator otherwise only
// learns about it when `serve` refuses to start.
func TestValidateConfigEndToEnd_AnomalyOutputBadDirectoryFails(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`listen: ":8080"
upstream: "http://localhost:9000"
policy_file: %q
audit:
  output: stdout
features:
  anomaly_detection: true
anomaly:
  output: %q
  window_seconds: 60
`, policyPath, filepath.Join(dir, "no-such-dir", "anomaly.jsonl"))
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	if out, err := exec.Command(binPath, "validate-config", "--config", configPath).CombinedOutput(); err == nil {
		t.Fatalf("expected a non-zero exit for an anomaly.output directory that doesn't exist, got: %s", out)
	}
}

// TestExportEvidenceEndToEnd_RenameFailureCleansUpTmpFile forces the
// os.Rename(tmpPath, output) failure branch in runExportEvidence by
// pointing -output at a path that already exists as a directory --
// renaming a file onto an existing directory fails ("file exists"/"is a
// directory") without needing to fake disk-full or cross-device errors.
// Asserts the leftover tmpPath (output + ".tmp") is cleaned up, matching
// the WriteBundle-failure and f.Close-failure branches right above it.
func TestExportEvidenceEndToEnd_RenameFailureCleansUpTmpFile(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(auditPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "wardline.yaml")
	config := fmt.Sprintf(`listen: ":8080"
upstream: "http://localhost:9000"
policy_file: %q
audit:
  output: %q
`, policyPath, auditPath)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	outputDir := filepath.Join(dir, "evidence-output")
	if err := os.Mkdir(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	tmpPath := outputDir + ".tmp"

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	out, err := exec.Command(binPath, "export-evidence",
		"--config", configPath,
		"-from", "2020-01-01T00:00:00Z",
		"-to", "2030-01-01T00:00:00Z",
		"-output", outputDir,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected export-evidence to fail when -output collides with an existing directory, got no error; output: %s", out)
	}
	if !bytes.Contains(out, []byte("failed to finalize output file")) {
		t.Fatalf("expected the rename-failure log message, got: %s", out)
	}
	if _, statErr := os.Stat(tmpPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected %s to be cleaned up after a rename failure, stat err = %v", tmpPath, statErr)
	}
}

// TestExportEvidenceEndToEnd_RealBundleFromRealBinary builds the real
// wardline binary, runs `serve` against a file-backed audit output,
// makes a couple of real proxied calls, stops the server, then runs
// `export-evidence` as a second subprocess against the same config and
// audit file, and inspects the resulting .tar.gz for the expected
// contents.
//
// This test is self-contained (does not reuse startWardline, since that
// helper doesn't expose the built binary path or config path needed to
// invoke a second export-evidence subprocess against the same audit
// file, and readBundleFile in main_test.go lives in package main, not
// package main_test, so it isn't reachable from this file).
func TestExportEvidenceEndToEnd_RealBundleFromRealBinary(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	listenAddr := reserveAddr(t)

	if err := os.WriteFile(policyPath, []byte(`
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: "%s"
`, listenAddr, upstream.URL, policyPath, auditPath)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	serveCmd := exec.Command(binPath, "serve", "--config", configPath)
	var serveStderr safeBuffer
	serveCmd.Stderr = &serveStderr
	if err := serveCmd.Start(); err != nil {
		t.Fatal(err)
	}
	serveWaiter := waitFor(serveCmd)
	t.Cleanup(func() {
		_ = serveCmd.Process.Kill()
		<-serveWaiter.done
	})
	// A bare TCP-dial readiness probe, not waitForServer's http.Get: an
	// actual HTTP request would itself be proxied and audited (as a
	// audit entry with Decision "error", since an empty body fails
	// JSON-RPC parsing -- "error" is an audit Decision value, not the
	// JSON-RPC -32700 "Parse error" code), throwing
	// off the exact audit_entry_count/decision-count assertions below.
	waitForListener(t, listenAddr)

	before := time.Now().Add(-time.Minute)
	allowResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (stderr: %s)", allowResp.StatusCode, serveStderr.String())
	}
	denyResp := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (stderr: %s)", denyResp.StatusCode, serveStderr.String())
	}
	after := time.Now().Add(time.Minute)

	_ = serveCmd.Process.Kill()
	<-serveWaiter.done

	outputPath := filepath.Join(dir, "evidence.tar.gz")
	exportCmd := exec.Command(binPath, "export-evidence",
		"--config", configPath,
		"--from", before.UTC().Format(time.RFC3339),
		"--to", after.UTC().Format(time.RFC3339),
		"--output", outputPath,
	)
	exportOut, err := exportCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("export-evidence failed: %v\n%s", err, exportOut)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read evidence bundle: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[hdr.Name] = content
	}

	var manifest struct {
		AuditEntryCount     int            `json:"audit_entry_count"`
		AuditDecisionCounts map[string]int `json:"audit_decision_counts"`
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
	if manifest.AuditEntryCount != 2 {
		t.Errorf("expected 2 audit entries, got %d", manifest.AuditEntryCount)
	}
	if manifest.AuditDecisionCounts["allow"] != 1 || manifest.AuditDecisionCounts["deny"] != 1 {
		t.Errorf("unexpected decision counts: %+v", manifest.AuditDecisionCounts)
	}
	if !bytes.Contains(files["audit.jsonl"], []byte(`"identity":"agent-abc123"`)) {
		t.Errorf("expected audit.jsonl to contain the real audit entries, got %s", files["audit.jsonl"])
	}
	if _, ok := files["checksums.txt"]; !ok {
		t.Error("expected checksums.txt in the bundle")
	}
}

// TestExportEvidenceEndToEnd_StdoutAuditOutputFailsLoud proves
// export-evidence refuses to run (and writes nothing) when the audit
// trail isn't queryable.
func TestExportEvidenceEndToEnd_StdoutAuditOutputFailsLoud(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")
	outputPath := filepath.Join(dir, "evidence.tar.gz")

	if err := os.WriteFile(policyPath, []byte(`default: allow`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: ":0"
upstream: "http://127.0.0.1:1"
policy_file: "%s"
audit:
  output: stdout
`, policyPath)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	exportCmd := exec.Command(binPath, "export-evidence",
		"--config", configPath,
		"--from", "2020-01-01T00:00:00Z",
		"--output", outputPath,
	)
	out, err := exportCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected export-evidence to fail when audit.output is stdout, got success: %s", out)
	}
	if !bytes.Contains(out, []byte("not queryable")) {
		t.Errorf("expected a clear \"not queryable\" message, got: %s", out)
	}
	if _, err := os.Stat(outputPath); err == nil {
		t.Error("expected no output file to be written on failure")
	}
}

// TestPolicyPackEndToEnd_InstalledPackIsEnforcedByRealServe builds the
// real wardline binary, installs the read-only-single-identity pack to a
// temp path via a real "policy-pack install" subprocess, then starts a
// real "serve" pointed at that installed file and proves the installed
// rules are genuinely enforced: the placeholder identity can call a
// tool the pack allows and is denied a tool it doesn't, and a completely
// different identity is denied by the pack's own default.
func TestPolicyPackEndToEnd_InstalledPackIsEnforcedByRealServe(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "installed-policy.yaml")

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// "--output" (double dash) on purpose, even though the README documents
	// "-output": Go's flag package treats both identically, and running the
	// double-dash form through the real binary here covers the form the
	// docs don't show.
	installCmd := exec.Command(binPath, "policy-pack", "install", "read-only-single-identity", "--output", policyPath)
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("policy-pack install failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("expected the installed policy file to exist: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	realListenAddr := reserveAddr(t)
	configPath := filepath.Join(dir, "wardline.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: stdout
`, realListenAddr, upstream.URL, policyPath)), 0644); err != nil {
		t.Fatal(err)
	}

	serveCmd := exec.Command(binPath, "serve", "--config", configPath)
	var serveStderr safeBuffer
	serveCmd.Stderr = &serveStderr
	if err := serveCmd.Start(); err != nil {
		t.Fatal(err)
	}
	waiter := waitFor(serveCmd)
	t.Cleanup(func() {
		_ = serveCmd.Process.Kill()
		<-waiter.done
	})
	waitForServer(t, "http://"+realListenAddr)

	allowedResp := postToolCall(t, realListenAddr, "REPLACE_WITH_YOUR_IDENTITY", "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the pack's allowed tool, got %d (stderr: %s)", allowedResp.StatusCode, serveStderr.String())
	}

	deniedResp := postToolCall(t, realListenAddr, "REPLACE_WITH_YOUR_IDENTITY", "delete_file")
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a tool the pack doesn't allow, got %d (stderr: %s)", deniedResp.StatusCode, serveStderr.String())
	}

	otherIdentityResp := postToolCall(t, realListenAddr, "someone-else", "read_file")
	if otherIdentityResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a different identity (pack's default: deny), got %d (stderr: %s)", otherIdentityResp.StatusCode, serveStderr.String())
	}
}

// TestHAEndToEnd_TwoReplicasShareSigningKeyAndRevocation is the actual
// "does HA work" proof for this cycle: two real wardline serve
// subprocesses, started with the SAME signing key file and the SAME
// postgres_storage DSN, simulating two replicas behind a load balancer.
// A token issued by hitting replica A's /credentials/token is used
// successfully against replica B (proving cross-replica signature
// verification), then a revocation issued against replica A is honored
// by replica B on the very next call (proving cross-replica revocation
// propagation through the shared Postgres table).
func TestHAEndToEnd_TwoReplicasShareSigningKeyAndRevocation(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTableE2E(t, dsn)

	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "policy.yaml")
	keyPath := filepath.Join(dir, "signing-key.pem")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	if err := os.WriteFile(policyPath, []byte(`default: allow`), 0644); err != nil {
		t.Fatal(err)
	}

	genKey := exec.Command("openssl", "genrsa", "-out", keyPath, "2048")
	if out, err := genKey.CombinedOutput(); err != nil {
		t.Fatalf("generate test signing key: %v\n%s", err, out)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	addrA := reserveAddr(t)
	addrB := reserveAddr(t)
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: agent-abc123
    secret: "test-secret-at-least-this-long"
`), 0644); err != nil {
		t.Fatal(err)
	}

	startReplica := func(listenAddr string) (*exec.Cmd, *cmdWaiter, *safeBuffer) {
		configPath := filepath.Join(dir, listenAddr+"-wardline.yaml")
		if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
features:
  credential_issuance: true
  postgres_storage: true
credential:
  identities_file: "%s"
  signing_key_file: "%s"
audit:
  postgres_dsn: "%s"
`, listenAddr, upstream.URL, policyPath, credentialsPath, keyPath, dsn)), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binPath, "serve", "--config", configPath)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start replica at %s: %v", listenAddr, err)
		}
		waiter := waitFor(cmd)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			<-waiter.done
		})
		waitForListener(t, listenAddr)
		return cmd, waiter, stderr
	}

	_, _, stderrA := startReplica(addrA)
	_, _, stderrB := startReplica(addrB)

	// Issue a token against replica A.
	tokenResp, err := http.Post("http://"+addrA+"/credentials/token", "application/json",
		strings.NewReader(`{"identity":"agent-abc123","secret":"test-secret-at-least-this-long"}`))
	if err != nil {
		t.Fatalf("issue token against replica A: %v", err)
	}
	defer func() { _ = tokenResp.Body.Close() }()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 issuing token from replica A, got %d (stderr: %s)", tokenResp.StatusCode, stderrA.String())
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenBody.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	// Use that token against replica B -- proves cross-replica signature
	// verification (same signing key file).
	callReq, err := http.NewRequest(http.MethodPost, "http://"+addrB, strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	callReq.Header.Set("Authorization", "Bearer "+tokenBody.Token)
	callResp, err := http.DefaultClient.Do(callReq)
	if err != nil {
		t.Fatalf("call replica B with replica A's token: %v", err)
	}
	_ = callResp.Body.Close()
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 calling replica B with replica A's token, got %d (stderr: %s)", callResp.StatusCode, stderrB.String())
	}

	// Revoke the identity against replica A.
	revokeReq, err := http.NewRequest(http.MethodPost, "http://"+addrA+"/credentials/revoke", strings.NewReader(`{"identity":"agent-abc123"}`))
	if err != nil {
		t.Fatal(err)
	}
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("revoke against replica A: %v", err)
	}
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 revoking against replica A, got %d (stderr: %s)", revokeResp.StatusCode, stderrA.String())
	}

	// The SAME token, now used against replica B again, must be rejected
	// -- proves cross-replica revocation propagation through the shared
	// Postgres table.
	callReq2, err := http.NewRequest(http.MethodPost, "http://"+addrB, strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	callReq2.Header.Set("Authorization", "Bearer "+tokenBody.Token)
	callResp2, err := http.DefaultClient.Do(callReq2)
	if err != nil {
		t.Fatalf("call replica B after revocation: %v", err)
	}
	_ = callResp2.Body.Close()
	// A revoked bearer token always fails at identityAuth.Authenticate and
	// returns 401 specifically; 403 is only ever returned for a policy
	// deny on an authenticated request, which can't happen here.
	if callResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected the revoked token to be rejected by replica B with 401, got %d (stderr: %s)", callResp2.StatusCode, stderrB.String())
	}
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres HA integration test")
	}
	return dsn
}

func dropRevokedIdentitiesTableE2E(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS revoked_identities`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_entries`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

// TestHealthEndToEnd_ReadyzFlipsToUnreadyDuringShutdown proves the real
// zero-downtime-rolling-deploy behavior: /readyz answers 503 starting the
// instant SIGTERM is sent, well before the process actually exits, so a
// polling Kubernetes readiness probe has time to pull the pod out of
// rotation during the drain window.
func TestHealthEndToEnd_ReadyzFlipsToUnreadyDuringShutdown(t *testing.T) {
	listenAddr, _, stderr, cmd, waiter := startWardline(t, "policy.yaml", `default: allow`, "")

	readyResp, err := http.Get("http://" + listenAddr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz before shutdown: %v", err)
	}
	_ = readyResp.Body.Close()
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /readyz before shutdown, got %d (stderr: %s)", readyResp.StatusCode, stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	// srv.Shutdown closes the listener to new connections essentially the
	// moment it's called, right after SetDraining(true) -- the window in
	// which a *new* connection can still land a 503 read is a handful of
	// scheduler ticks wide, not the whole shutdown-timeout duration (that
	// duration bounds draining *existing* in-flight connections instead).
	// A 20ms poll interval is too coarse to reliably land inside that
	// window under load (observed flaking in a full `go test ./...` run
	// alongside many other subprocess-spawning tests); 2ms gives ~2500
	// attempts over the 5s deadline instead of ~250, without changing
	// what's being asserted.
	deadline := time.Now().Add(5 * time.Second)
	sawUnready := false
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + listenAddr + "/readyz")
		if err != nil {
			break // server has finished shutting down
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code == http.StatusServiceUnavailable {
			sawUnready = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !sawUnready {
		t.Fatalf("expected /readyz to return 503 at some point during the shutdown drain, never observed it (stderr: %s)", stderr.String())
	}

	<-waiter.done // drain the process exit so t.Cleanup's own Kill+Wait doesn't race this test's explicit SIGTERM
}

// TestHealthEndToEnd_HealthzAndReadyzAreNotAuditedOrProxied is self-contained
// (does not reuse startWardline) because startWardline's own readiness
// probe (waitForServer) is a bare http.Get through the real proxy path,
// which itself lands an "error"-decision audit entry before this test's
// body even runs -- defeating the "zero audit entries" assertion below
// deterministically, not flakily. Same reasoning as
// TestExportEvidenceEndToEnd_RealBundleFromRealBinary's use of
// waitForListener over waitForServer.
func TestHealthEndToEnd_HealthzAndReadyzAreNotAuditedOrProxied(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	listenAddr := reserveAddr(t)

	if err := os.WriteFile(policyPath, []byte(`default: allow`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: "%s"
`, listenAddr, upstream.URL, policyPath, auditPath)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	stderr := &safeBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wardline: %v", err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForListener(t, listenAddr)

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get("http://" + listenAddr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from %s, got %d (stderr: %s)", path, resp.StatusCode, stderr.String())
		}
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected /healthz and /readyz to produce zero audit entries, got: %s", data)
	}
}
