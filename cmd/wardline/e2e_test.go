package main_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// TestServeEndToEnd_MalformedJSONBodyRejected proves the baseline hot
// path's parse-error edge case end to end against a real running server:
// unparsable JSON gets a 400 with a JSON-RPC -32700 parse-error envelope
// (not a 5xx, not a hang), and the rejection still produces an audit
// entry (decision "error") rather than silently dropping the request off
// the audit trail — a swallowed error on this path would be a silent
// security gap per this repo's Go conventions.
func TestServeEndToEnd_MalformedJSONBodyRejected(t *testing.T) {
	listenAddr, stdout, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, "")

	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr, bytes.NewBufferString("not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON body, got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}

	var rpcErr struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcErr); err != nil {
		t.Fatalf("response body is not valid JSON-RPC error envelope: %v (body: %s)", err, body)
	}
	if rpcErr.Error.Code != -32700 {
		t.Fatalf("expected JSON-RPC parse-error code -32700, got %d (body: %s)", rpcErr.Error.Code, body)
	}

	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	var lastLine string
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			lastLine = lines[i]
			break
		}
	}
	if lastLine == "" {
		t.Fatalf("expected an audit entry for the rejected malformed request, got no audit output: %q", stdout.String())
	}
	var entry struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal([]byte(lastLine), &entry); err != nil {
		t.Fatalf("audit log line is not valid JSON: %v (line: %s)", err, lastLine)
	}
	if entry.Decision != "error" {
		t.Fatalf("expected audit decision %q for the malformed request, got %q (line: %s)", "error", entry.Decision, lastLine)
	}
}

// TestServeEndToEnd_ResourcesAndPromptsGatedByPolicy is the widening
// feature's real end-to-end proof, mirroring the empirical-proof
// discipline docs/superpowers/specs/2026-07-27-mcp-protocol-passthrough-design.md
// established: a real compiled wardline binary, a real YAML policy file
// with method-scoped rules, proves a matching resources/read succeeds, a
// non-matching one is denied, and a matching prompts/get succeeds too —
// resources/*/prompts/* are no longer unconditional passthrough. See
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
func TestServeEndToEnd_ResourcesAndPromptsGatedByPolicy(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    method: "resources/read"
    tool: "file:///data/report.csv"
    effect: allow
  - identity: "agent-abc123"
    method: "prompts/get"
    tool: "*"
    effect: allow
default: deny
`, "")

	allowedRead := postToolCallBody(t, listenAddr, "agent-abc123", `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///data/report.csv"}}`)
	if allowedRead.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a resources/read matching the allow rule, got %d (stderr: %s)", allowedRead.StatusCode, stderr.String())
	}

	deniedRead := postToolCallBody(t, listenAddr, "agent-abc123", `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///etc/passwd"}}`)
	if deniedRead.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a resources/read NOT matching the allow rule (falls to default deny), got %d (stderr: %s)", deniedRead.StatusCode, stderr.String())
	}

	allowedPrompt := postToolCallBody(t, listenAddr, "agent-abc123", `{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"summarize"}}`)
	if allowedPrompt.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a prompts/get matching the wildcard allow rule, got %d (stderr: %s)", allowedPrompt.StatusCode, stderr.String())
	}

	// A tools/call to the same identity, with no tools/call rule defined,
	// still falls to the default deny -- proves the resources/prompts
	// rules above didn't accidentally widen into the tools/call method
	// space (each rule is method-scoped, see the design doc's Matcher
	// changes).
	deniedToolCall := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if deniedToolCall.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a tools/call with no matching tools/call rule, got %d (stderr: %s)", deniedToolCall.StatusCode, stderr.String())
	}

	// A true protocol-lifecycle method (not resources/*/prompts/*) still
	// passes through unconditionally, unaffected by this widening.
	initResp := postToolCallBody(t, listenAddr, "agent-abc123", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for initialize (still unconditional passthrough), got %d (stderr: %s)", initResp.StatusCode, stderr.String())
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

// postToolCallWithTenant is like postToolCall but also sets
// X-Wardline-Tenant, for tests exercising per-tenant budget overrides
// (HeaderIdentity resolves tenant from this header — see
// internal/features/proxy/adapter/identity.go).
func postToolCallWithTenant(t *testing.T, listenAddr, identity, tenantName, tool string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q}}`, tool)
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	req.Header.Set("X-Wardline-Tenant", tenantName)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	return resp
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

// TestServeEndToEnd_BudgetTenantOverrideANDSemantics proves the tenant
// override is checked *alongside*, not *instead of*, the identity budget —
// InMemoryLimiter.Allow's doc comment promises "in addition to, not
// instead of" (internal/features/budget/adapter/inmemory.go), and this is
// the real-server proof, not just the fake-clock unit test. The global
// default (100/window) is generous enough that identity alone would never
// throttle here; only a strict per-tenant override (1/window) can produce
// the 429 below. A second identity under the *same* tenant proves the
// override is scoped by tenant, not shared across every identity as a
// single global bucket. A third identity under an unlisted tenant proves
// tenants with no override configured fall through to the generous
// default untouched, per SetTenantLimit's doc comment.
func TestServeEndToEnd_BudgetTenantOverrideANDSemantics(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-a"
    tool: "read_file"
    effect: allow
  - identity: "agent-b"
    tool: "read_file"
    effect: allow
  - identity: "agent-c"
    tool: "read_file"
    effect: allow
default: deny
`, `features:
  budget_enforcement: true
budget:
  requests_per_window: 100
  window_seconds: 1
  tenants:
    acme:
      requests_per_window: 1
      window_seconds: 1`)

	firstResp := postToolCallWithTenant(t, listenAddr, "agent-a", "acme", "read_file")
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the first acme call within the tenant override, got %d (stderr: %s)", firstResp.StatusCode, stderr.String())
	}

	secondResp := postToolCallWithTenant(t, listenAddr, "agent-a", "acme", "read_file")
	if secondResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429: acme's tenant override (1/window) should throttle even though the identity default (100/window) alone would allow it, got %d (stderr: %s)", secondResp.StatusCode, stderr.String())
	}

	// A different identity under the same tenant shares the tenant
	// bucket -- the override is per-tenant, not per-identity -- so it's
	// throttled too even though it has never called before.
	otherIdentitySameTenant := postToolCallWithTenant(t, listenAddr, "agent-b", "acme", "read_file")
	if otherIdentitySameTenant.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429: a second identity under the same over-budget tenant should also be throttled by the shared tenant bucket, got %d (stderr: %s)", otherIdentitySameTenant.StatusCode, stderr.String())
	}

	// A tenant with no override configured falls through to the generous
	// global default untouched.
	unoverriddenTenant := postToolCallWithTenant(t, listenAddr, "agent-c", "widgets-inc", "read_file")
	if unoverriddenTenant.StatusCode != http.StatusOK {
		t.Fatalf("expected 200: a tenant with no configured override should use the global default, got %d (stderr: %s)", unoverriddenTenant.StatusCode, stderr.String())
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
	dsn := testDSN(t)
	dropAuditEntriesTableE2E(t, dsn)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() { _ = db.Close() }()

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

// TestServeEndToEnd_PostgresStorageWithoutBudgetEnforcement proves that
// postgres_storage alone does NOT stand up the Postgres budget limiter:
// budget_enforcement is its own feature flag, and an operator who never
// turned it on must not pay for the budget_buckets table, the extra
// connection pool, or a possible os.Exit(1) on limiter init failure.
// Asserted two ways — no Postgres-specific budget log lines, and the
// budget_buckets relation genuinely absent from the database after a
// real proxied call — so this fails loudly if the flag gate regresses.
func TestServeEndToEnd_PostgresStorageWithoutBudgetEnforcement(t *testing.T) {
	dsn := testDSN(t)
	dropBudgetBucketsTableE2E(t, dsn)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() { _ = db.Close() }()

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `default: allow`,
		"features:\n  postgres_storage: true\nbudget:\n  requests_per_window: 1\n  window_seconds: 60\naudit:\n  postgres_dsn: \""+dsn+"\"\n")

	// Two calls with a requests_per_window of 1: with budget_enforcement
	// off, the Checker no-ops and both must be admitted regardless of
	// which Limiter happens to back it.
	for i := 0; i < 2; i++ {
		resp := postToolCall(t, addr, "agent-1", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: expected 200 with budget_enforcement off, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}

	if strings.Contains(stderr.String(), "budget enforcement backed by postgres") {
		t.Errorf("expected no postgres budget limiter with budget_enforcement off; stderr: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "budget enforcement is in-process only") {
		t.Errorf("expected no single-replica warning for a disabled feature; stderr: %s", stderr.String())
	}

	var relation sql.NullString
	if err := db.QueryRow(`SELECT to_regclass($1)::text`, testSchema+".budget_buckets").Scan(&relation); err != nil {
		t.Fatalf("check for budget_buckets table: %v", err)
	}
	if relation.Valid {
		t.Errorf("expected budget_buckets NOT to be created when budget_enforcement is off, but found relation %q", relation.String)
	}
}

func dropBudgetBucketsTableE2E(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS budget_buckets`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
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

// postCredentialsRefresh posts refreshToken to /credentials/refresh --
// the real-binary counterpart to postCredentialsToken, exchanging a
// refresh token for a new (access, refresh) pair instead of the
// original bootstrap secret.
func postCredentialsRefresh(t *testing.T, listenAddr, refreshToken string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"refresh_token":%q}`, refreshToken)
	resp, err := http.Post("http://"+listenAddr+"/credentials/refresh", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// postCredentialsTokenWithHeader posts an empty-bodied
// /credentials/token request carrying headerValue in headerName --
// simulates a terminating mTLS proxy/mesh forwarding an already-verified
// SPIFFE ID, per the mtls bootstrap source's design (see
// docs/superpowers/specs/2026-08-01-mtls-spiffe-bootstrap-design.md). An
// empty headerValue omits the header entirely (simulating a caller that
// never went through the terminating proxy at all), matching how a real
// http.Header never has a header explicitly set to empty by a client
// that simply didn't send it.
func postCredentialsTokenWithHeader(t *testing.T, listenAddr, headerName, headerValue string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/credentials/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if headerValue != "" {
		req.Header.Set(headerName, headerValue)
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

// TestServeEndToEnd_JWKSEndpointServesIssuerKey proves GET
// /credentials/jwks is real end-to-end: a real running server serves a
// JWKS whose kid matches the kid embedded in a freshly-issued token, so
// a standard JWKS consumer could verify Wardline-issued tokens.
func TestServeEndToEnd_JWKSEndpointServesIssuerKey(t *testing.T) {
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

	// Fetch the JWKS.
	jwksResp, err := http.Get("http://" + listenAddr + "/credentials/jwks")
	if err != nil {
		t.Fatalf("GET /credentials/jwks: %v", err)
	}
	defer func() { _ = jwksResp.Body.Close() }()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /credentials/jwks, got %d (stderr: %s)", jwksResp.StatusCode, stderr.String())
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("invalid JWKS response: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly 1 key in the JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].Alg != "RS256" || jwks.Keys[0].Kid == "" {
		t.Errorf("unexpected JWKS key: %+v", jwks.Keys[0])
	}

	// Issue a token and confirm its kid header matches the JWKS key's kid.
	tokenResp := postCredentialsToken(t, listenAddr, "a-long-random-registration-secret")
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping, got %d", tokenResp.StatusCode)
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	_ = tokenResp.Body.Close()

	// The JWT header is the first base64url segment; decode it and read kid.
	parts := strings.SplitN(tokenBody.Token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected a 3-segment JWT, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse JWT header: %v", err)
	}
	if header.Kid != jwks.Keys[0].Kid {
		t.Errorf("expected the token's kid %q to match the JWKS key's kid %q", header.Kid, jwks.Keys[0].Kid)
	}
}

// TestServeEndToEnd_SigningKeyRotation proves the rotation window works
// through a real running binary: the server signs with a NEW key while
// still accepting the OLD key for verification. A token minted under the
// old key (by a separate short-lived process started with only the old
// key) is presented to the rotated server and successfully authenticates
// a real proxied call.
func TestServeEndToEnd_SigningKeyRotation(t *testing.T) {
	dir := t.TempDir()
	oldKeyPath := filepath.Join(dir, "old-key.pem")
	newKeyPath := filepath.Join(dir, "new-key.pem")
	writeE2ERSAKey(t, oldKeyPath)
	writeE2ERSAKey(t, newKeyPath)

	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: agent-abc123
    secret: "a-long-random-registration-secret"
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Phase 1: a server using ONLY the old key mints a token.
	oldAddr, _, oldStderr, oldCmd, oldWaiter := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  credential_issuance: true
credential:
  identities_file: "%s"
  signing_key_file: "%s"`, credentialsPath, oldKeyPath))

	tokenResp := postCredentialsToken(t, oldAddr, "a-long-random-registration-secret")
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping on the old-key server, got %d (stderr: %s)", tokenResp.StatusCode, oldStderr.String())
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	_ = tokenResp.Body.Close()
	oldKeyToken := tokenBody.Token
	// Stop the old-key server so its port frees up before phase 2.
	_ = oldCmd.Process.Kill()
	<-oldWaiter.done

	// Phase 2: a NEW server signs with the new key but lists the old key
	// as a previous (verification-only) key -- the rotation window.
	rotatedAddr, _, rotatedStderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  credential_issuance: true
credential:
  identities_file: "%s"
  signing_key_file: "%s"
  previous_signing_key_files:
    - "%s"`, credentialsPath, newKeyPath, oldKeyPath))

	// The old-key token still authenticates a real proxied call against
	// the rotated server.
	resp := postToolCallWithBearer(t, rotatedAddr, oldKeyToken, "read_file")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the old-key token to still verify during the rotation window, got %d (stderr: %s)", resp.StatusCode, rotatedStderr.String())
	}
}

// writeE2ERSAKey writes a fresh 2048-bit PKCS8 RSA private key PEM to path.
func writeE2ERSAKey(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// TestServeEndToEnd_RefreshTokenLifecycle proves the full refresh-token
// lifecycle over a real HTTP request through the real binary: bootstrap
// returns both an access and a refresh token; a short, test-configured
// access_token_ttl_seconds makes expiry actually observable within the
// test's own runtime; the refresh token exchanges for a new working
// access token; the OLD refresh token is rejected afterward (single-use
// rotation); and revoking the identity invalidates the NEW refresh token
// too (RevokeAllForIdentity), not just the access token.
func TestServeEndToEnd_RefreshTokenLifecycle(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: agent-abc123
    secret: "a-long-random-registration-secret"
`), 0644); err != nil {
		t.Fatal(err)
	}

	// access_token_ttl_seconds is 2, not the brief's originally suggested
	// 1 -- lestrrat-go/jwx/v3's NumericDate marshals exp with whole-second
	// (floored) precision (see JWTIssuerVerifier.Issue), so a freshly
	// issued token's REAL remaining lifetime is only (ttl-1, ttl] seconds,
	// not a full ttl seconds. With ttl=1 that range is (0,1] -- the
	// "access token works immediately" assertion below could race a
	// token that's already expired by the time the request lands. ttl=2
	// guarantees at least 1 full second of real headroom for that
	// assertion. This is the same fix already applied to this project's
	// own JWTIssuerVerifier TTL tests (see jwt_test.go and its commit
	// "fix(credential): use whole-second TTLs in JWTIssuerVerifier's TTL
	// tests"), which uses the identical 2s TTL / 2100ms sleep pairing.
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  credential_issuance: true
credential:
  identities_file: "%s"
  access_token_ttl_seconds: 2
  refresh_token_ttl_seconds: 3600`, credentialsPath))

	// Bootstrap: expect BOTH an access token and a refresh token.
	tokenResp := postCredentialsToken(t, listenAddr, "a-long-random-registration-secret")
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping, got %d (stderr: %s)", tokenResp.StatusCode, stderr.String())
	}
	var bootstrapBody struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&bootstrapBody); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	_ = tokenResp.Body.Close()
	if bootstrapBody.Token == "" || bootstrapBody.RefreshToken == "" {
		t.Fatal("expected non-empty access and refresh tokens from bootstrap")
	}

	// The access token works immediately.
	allowedResp := postToolCallWithBearer(t, listenAddr, bootstrapBody.Token, "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for an allowed call with a fresh access token, got %d (stderr: %s)", allowedResp.StatusCode, stderr.String())
	}

	// Wait past the configured 2-second access-token TTL.
	time.Sleep(2100 * time.Millisecond)
	expiredResp := postToolCallWithBearer(t, listenAddr, bootstrapBody.Token, "read_file")
	if expiredResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an access token past its configured 2s TTL, got %d", expiredResp.StatusCode)
	}

	// Refresh: exchange the refresh token for a NEW working access token.
	refreshResp := postCredentialsRefresh(t, listenAddr, bootstrapBody.RefreshToken)
	if refreshResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 refreshing, got %d (stderr: %s)", refreshResp.StatusCode, stderr.String())
	}
	var refreshedBody struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshedBody); err != nil {
		t.Fatalf("invalid refresh response: %v", err)
	}
	_ = refreshResp.Body.Close()
	if refreshedBody.Token == "" || refreshedBody.RefreshToken == "" {
		t.Fatal("expected non-empty NEW access and refresh tokens from refresh")
	}
	if refreshedBody.RefreshToken == bootstrapBody.RefreshToken {
		t.Fatal("expected refresh to rotate to a DIFFERENT refresh token")
	}

	newAccessResp := postToolCallWithBearer(t, listenAddr, refreshedBody.Token, "read_file")
	if newAccessResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for an allowed call with the new access token, got %d (stderr: %s)", newAccessResp.StatusCode, stderr.String())
	}

	// The OLD refresh token is now rejected (single-use rotation).
	reusedOldResp := postCredentialsRefresh(t, listenAddr, bootstrapBody.RefreshToken)
	if reusedOldResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 reusing the already-rotated-away refresh token, got %d", reusedOldResp.StatusCode)
	}

	// Revoke the identity from loopback.
	revokeReq, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/credentials/revoke", strings.NewReader(`{"identity":"agent-abc123"}`))
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

	// The NEW refresh token (still within its 1-hour TTL, never used
	// again yet) is now ALSO rejected -- proves RevocationService's
	// RevokeAllForIdentity call actually reaches the live refresh store,
	// not just the access-token Revoker.
	revokedRefreshResp := postCredentialsRefresh(t, listenAddr, refreshedBody.RefreshToken)
	if revokedRefreshResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 refreshing with a since-revoked identity's still-otherwise-valid refresh token, got %d", revokedRefreshResp.StatusCode)
	}
}

// TestServeEndToEnd_MTLSBootstrap proves the full mtls-bootstrap-source
// flow over a real HTTP request through the real binary: a
// terminating-proxy-forwarded SPIFFE ID header bootstraps a real bearer
// token that then proxies a real allowed tool call, while a missing
// header and an unmapped SPIFFE ID both fail closed with a generic 401.
// No real X.509/mTLS handshake anywhere -- see this plan's Global
// Constraints for why that's the correct test surface for this feature.
func TestServeEndToEnd_MTLSBootstrap(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
`), 0644); err != nil {
		t.Fatal(err)
	}

	const headerName = "X-Wardline-Verified-Spiffe-Id"
	const mappedSpiffeID = "spiffe://example.org/ns/prod/sa/payments-worker"

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "payments-worker"
    tool: "read_file"
    effect: allow
default: deny
`, fmt.Sprintf(`features:
  credential_issuance: true
credential:
  identities_file: "%s"
  bootstrap_source: "mtls"
  mtls:
    header: "%s"`, credentialsPath, headerName))

	// A missing header (no terminating proxy in front of this request)
	// is rejected, no token issued.
	missingResp := postCredentialsTokenWithHeader(t, listenAddr, headerName, "")
	if missingResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a missing header, got %d (stderr: %s)", missingResp.StatusCode, stderr.String())
	}

	// An unmapped SPIFFE ID (a real terminating proxy verified SOME
	// cert, but not one this Wardline instance's operator registered) is
	// rejected the same way.
	unmappedResp := postCredentialsTokenWithHeader(t, listenAddr, headerName, "spiffe://example.org/ns/prod/sa/some-other-worker")
	if unmappedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unmapped spiffe id, got %d (stderr: %s)", unmappedResp.StatusCode, stderr.String())
	}

	// A mapped SPIFFE ID bootstraps a real token.
	tokenResp := postCredentialsTokenWithHeader(t, listenAddr, headerName, mappedSpiffeID)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping a mapped spiffe id, got %d (stderr: %s)", tokenResp.StatusCode, stderr.String())
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

	// A raw X-Wardline-Identity header alone (no bearer token, no
	// terminating-proxy header) must not work -- the same regression
	// TestServeEndToEnd_CredentialIssuance guards for the other bootstrap
	// sources.
	legacyHeaderResp := postToolCall(t, listenAddr, "payments-worker", "read_file")
	if legacyHeaderResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a raw X-Wardline-Identity header with credential_issuance on, got %d", legacyHeaderResp.StatusCode)
	}
}

// TestServeEndToEnd_MTLSTrustedHeaderStrippedBeforeUpstream proves the
// real deployment shape for bootstrap_source: mtls end to end: the
// terminating mesh sets its trusted SPIFFE-ID header on every request
// that reaches Wardline, not just the bootstrap call, so it is still
// present on the proxied tool call that follows the same one that
// bootstrapped the token. Confirms the untrusted upstream MCP server
// never receives it -- the same guarantee
// TestHandler_TrustedIdentityHeaderStrippedBeforeForwarding proves at the
// unit level, proven here through the real binary and a real proxied hop.
func TestServeEndToEnd_MTLSTrustedHeaderStrippedBeforeUpstream(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
`), 0644); err != nil {
		t.Fatal(err)
	}

	const headerName = "X-Wardline-Verified-Spiffe-Id"
	const mappedSpiffeID = "spiffe://example.org/ns/prod/sa/payments-worker"

	var mu sync.Mutex
	var gotTrustedHeader string
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotTrustedHeader = r.Header.Get(headerName)
		upstreamHit = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
rules:
  - identity: "payments-worker"
    tool: "read_file"
    effect: allow
default: deny
`), 0644); err != nil {
		t.Fatal(err)
	}

	listenAddr := reserveAddr(t)
	configPath := filepath.Join(dir, "wardline.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
features:
  credential_issuance: true
credential:
  identities_file: "%s"
  bootstrap_source: "mtls"
  mtls:
    header: "%s"
audit:
  output: stdout
`, listenAddr, upstream.URL, policyPath, credentialsPath, headerName)), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	var stderr safeBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForServer(t, "http://"+listenAddr)

	// Bootstrap a real token via the trusted header.
	tokenResp := postCredentialsTokenWithHeader(t, listenAddr, headerName, mappedSpiffeID)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 bootstrapping a mapped spiffe id, got %d (stderr: %s)", tokenResp.StatusCode, stderr.String())
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	_ = tokenResp.Body.Close()

	// The real deployment shape: the mesh sets this header on ALL traffic
	// reaching Wardline, not just the bootstrap request -- so it's still
	// present here, alongside the bearer token, on the proxied tool call.
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr,
		bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenBody.Token)
	req.Header.Set(headerName, mappedSpiffeID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the allowed proxied call, got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if !upstreamHit {
		t.Fatal("expected the upstream to be reached for an allowed call")
	}
	if gotTrustedHeader != "" {
		t.Errorf("expected the upstream to never see the trusted mtls header, got %q", gotTrustedHeader)
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
	dsn := testDSN(t)
	dropAuditEntriesTableE2E(t, dsn)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() { _ = db.Close() }()

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

// TestServeEndToEnd_AnomalyBaselinePersistsAcrossRestart proves the
// actual headline property this plan exists for: an identity's rate-spike
// baseline (built by real traffic against one wardline process) survives
// that process being killed and a fresh one started against the same
// Postgres database -- not just that PostgresBaselineStore round-trips
// in isolation. Requires WARDLINE_TEST_POSTGRES_DSN pointing at a real
// Postgres instance; skips otherwise (see testDSN).
//
// Timing design: window_seconds=2 is deliberately short, not generous --
// the property this test needs is the OPPOSITE of
// TestServeEndToEnd_AnomalyDetectionRateSpike's headroom concern. Five
// quick local calls plus a 1500ms sleep for a GC save (gc_interval_seconds=1)
// happen well inside process1's original window (no rollover -- no
// further calls occur during that sleep to trigger one), so the
// snapshot saved to Postgres just before process1 is killed is exactly
// cur.total=5, prev.total=0. What matters next is that process2's OWN
// first request arrives measurably more than window_seconds after that
// saved windowStart -- true here because killing process1, running `go
// build` again for process2's binary (startWardline always rebuilds),
// and waiting for it to become ready reliably takes several real
// seconds, comfortably past a 2s window. That gap is what makes
// process2's very first Publish call roll the window over immediately
// in memory: the restored cur (5) becomes the new prev, which is
// exactly the persisted baseline this test is proving survived. A
// window_seconds large enough to survive a loaded CI runner mid-burst
// (as the rate-spike test above needs) would instead risk staying
// UNDER the restart gap here and never rolling over at all -- the
// failure mode this test actually needs to avoid. rate_multiplier=3 /
// min_calls=1 then means any cur.total > 15 within process2's own
// first window trips rate_spike -- 20 calls clears that with room to
// spare, and lands well inside a 2s window on localhost.
func TestServeEndToEnd_AnomalyBaselinePersistsAcrossRestart(t *testing.T) {
	dsn := testDSN(t)
	dropAnomalyBaselinesTableE2E(t, dsn)

	config := fmt.Sprintf(`features:
  web_ui: true
  anomaly_detection: true
  postgres_storage: true
anomaly:
  output: stdout
  window_seconds: 2
  gc_interval_seconds: 1
  rate_spike:
    enabled: true
    rate_multiplier: 3
    min_calls: 1
audit:
  postgres_dsn: %q
`, dsn)

	listenAddr1, _, stderr1, cmd1, waiter1 := startWardline(t, "policy.yaml", "default: allow", config)

	// Establish a baseline of 5 calls, all within process1's first window
	// (window_seconds=2, five sequential local HTTP round-trips take
	// nowhere near that long).
	for i := 0; i < 5; i++ {
		callResp := postToolCall(t, listenAddr1, "alice", "read_file")
		_ = callResp.Body.Close()
	}
	// Let at least one GC tick (gc_interval_seconds=1) persist that
	// state -- no further calls are made during this sleep, so no window
	// rollover happens; the snapshot saved is exactly cur.total=5,
	// prev.total=0.
	time.Sleep(1500 * time.Millisecond)

	// Kill process1 (simulating a restart) and block until it has
	// actually exited -- reading the same waiter startWardline's own
	// cleanup will later read from, per waitFor's doc comment, rather
	// than calling cmd1.Wait() a second time. Waiting here (not just
	// killing) matters: process2 below must not race process1 still
	// holding its Postgres connection.
	if err := cmd1.Process.Kill(); err != nil {
		t.Fatalf("kill process1: %v", err)
	}
	select {
	case <-waiter1.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("process1 did not exit within 15s of kill (stderr1: %s)", stderr1.String())
	}

	listenAddr2, _, stderr2, _, _ := startWardline(t, "policy.yaml", "default: allow", config)

	// A burst well above what a truly-reset (never-restarted) baseline of
	// zero would allow -- see this test's doc comment for why the
	// persisted cur=5 becomes process2's prev on its very first call, and
	// why 20 calls reliably trips rate_multiplier=3 against it.
	for i := 0; i < 20; i++ {
		callResp := postToolCall(t, listenAddr2, "alice", "read_file")
		_ = callResp.Body.Close()
	}

	resp, err := http.Get("http://" + listenAddr2 + "/dashboard/api/anomalies")
	if err != nil {
		t.Fatalf("fetch anomalies: %v (stderr2: %s)", err, stderr2.String())
	}
	defer func() { _ = resp.Body.Close() }()
	var alerts []struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		t.Fatalf("decode anomalies: %v", err)
	}
	found := false
	for _, a := range alerts {
		if a.Kind == "rate_spike" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a rate_spike anomaly on the fresh process (proving the baseline survived the restart), got alerts: %+v (stderr2: %s)", alerts, stderr2.String())
	}
}

// dropAnomalyBaselinesTableE2E drops anomaly_baselines before a
// cross-restart test runs, matching dropAuditEntriesTableE2E /
// dropBudgetBucketsTableE2E's own cleanup pattern -- a stale row from a
// previous run (same identity "alice", same testSchema) would otherwise
// restore an unrelated leftover baseline instead of the one this test
// establishes itself.
func dropAnomalyBaselinesTableE2E(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS anomaly_baselines`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

// TestServeEndToEnd_MLScoreAutoBlock proves ml_score's z-score detector
// and auto_block's time-bounded block are wired together end to end
// through the real binary: a wild post-baseline outlier window both
// fires an ml_score anomaly and blocks the offending identity via
// main.go's blockChecker wiring into proxyadapter.NewHandler, and the
// very next call from that identity is rejected with a "blocked"
// decision -- while an unrelated identity is entirely unaffected, since
// the block is per-identity, not a global kill switch.
func TestServeEndToEnd_MLScoreAutoBlock(t *testing.T) {
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
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 2   # below the example config's 5: this test's baseline windows are 2-3 calls, which a floor of 5 would skip entirely
  auto_block:
    enabled: true
    score_threshold: 3.0
    block_duration_seconds: 30`, anomalyPath))

	doCall := func(identity, tool string) {
		resp := postToolCall(t, listenAddr, identity, tool)
		_ = resp.Body.Close()
	}

	// 10 baseline windows, alternating 2 vs 3 calls and 1 vs 2 tools so each
	// mlFeatureState baseline has real, non-zero variance to compare the
	// outlier window against -- a zero-variance baseline makes
	// onlineStat.ZScore() return 0 unconditionally, which would never clear
	// auto_block's threshold regardless of how wild the outlier window
	// below is. 10, not the bare minimum 8 (minSamplesForZScore): the
	// outlier window is scored once mlStats holds 10 samples, so a single
	// dropped or mis-timed window still leaves margin above the floor
	// instead of silently turning every z-score into 0 and failing this
	// test for a reason that looks nothing like a timing flake.
	// window_seconds is 3, not 1, purely for timing headroom -- same
	// reasoning as TestServeEndToEnd_AnomalyDetectionRateSpike's 3s window.
	for i := 0; i < 5; i++ {
		doCall("alice", "read_file")
		doCall("alice", "read_file")
		time.Sleep(3100 * time.Millisecond) // rotate: scores the 2-call window
		doCall("alice", "read_file")
		doCall("alice", "list_dir")
		doCall("alice", "list_dir")
		time.Sleep(3100 * time.Millisecond) // rotate: scores the 3-call window
	}

	// Wild outlier window: many distinct tools in a tight burst, far above
	// the established baseline's rate and tool-diversity mean.
	for i := 0; i < 30; i++ {
		doCall("alice", fmt.Sprintf("tool_%d", i))
	}
	time.Sleep(3100 * time.Millisecond)
	// This call's Publish is the one that rotates and scores the wild
	// window (now st.prev) against the established baseline -- if the
	// score clears auto_block.score_threshold, BlockChecker.Block runs
	// synchronously inside it, before this request's own response
	// returns.
	doCall("alice", "read_file")

	data, err := os.ReadFile(anomalyPath)
	if err != nil {
		t.Fatalf("failed to read anomaly output: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Contains(data, []byte(`"kind":"ml_score"`)) {
		t.Fatalf("expected an ml_score anomaly line in %s, got: %s", anomalyPath, data)
	}
	// Name the feature that must have driven the score, not just "some
	// ml_score anomaly fired": asserting the driving feature catches a
	// regression that still fires an anomaly but for the wrong reason. The
	// outlier window is 30 calls over 30 distinct tools against a baseline
	// alternating 2-3 calls over 1-2 distinct tools, so both volumetric
	// features fire hard and tool_diversity leads by a nose. This config's
	// min_calls of 2 puts both of them in the sub-quantum zone zCount's count
	// floor exists for -- distinct-tool count has baseline mean 1.5 (relative
	// floor 0.15*1.5 = 0.225) and call rate mean 2.5 (relative floor 0.375),
	// both well under one whole tool/call -- so each is floored at
	// max(1.0, sqrt(mean)): 1.2247 for diversity and 1.5811 for rate. The
	// outlier scores z_diversity = (30-1.5)/1.2247 = 23.27, comfortably past
	// call_rate's z_rate = (30-2.5)/1.5811 = 17.39. Neither depends on the raw
	// sample stddev at all, which makes this assertion more deterministic than
	// the pre-round-10 54.1-vs-52.2 it replaces, not less -- and round 11's
	// sqrt(mean) floor widens diversity's lead rather than narrowing it, since
	// the smaller-mean feature gets the smaller divisor. Flooring only one of
	// the two would invert the result: with diversity floored and call_rate
	// not, call_rate's un-floored 52.2 wins on an artifact. 30 distinct tools from an identity that normally
	// touches 1-2 is textbook enumeration, so diversity leading is the
	// right answer here -- it took the lead only once that feature was
	// scored as a raw distinct-tool count instead of distinct/total, a
	// ratio that pinned this window to its own 1.0 ceiling (z = 4.7) no
	// matter how many tools the burst actually swept.
	if !bytes.Contains(data, []byte(`(driving feature: tool_diversity)`)) {
		t.Fatalf("expected the ml_score anomaly to be driven by tool_diversity in %s, got: %s", anomalyPath, data)
	}

	blockedResp := postToolCall(t, listenAddr, "alice", "read_file")
	defer func() { _ = blockedResp.Body.Close() }()
	if blockedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for the auto-blocked identity, got %d (stderr: %s)", blockedResp.StatusCode, stderr.String())
	}
	if retryAfter := blockedResp.Header.Get("Retry-After"); retryAfter == "" {
		t.Error("expected a Retry-After header on the blocked response")
	}

	unblockedResp := postToolCall(t, listenAddr, "bob", "read_file")
	defer func() { _ = unblockedResp.Body.Close() }()
	if unblockedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a different, non-blocked identity, got %d (stderr: %s)", unblockedResp.StatusCode, stderr.String())
	}

	// web_ui's dashboardadapter.NewHandler blocked wiring: the same
	// BlockChecker main.go handed to the proxy handler above must also be
	// reachable read-only via the dashboard.
	blockedListResp, err := http.Get("http://" + listenAddr + "/dashboard/api/anomalies/blocked")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockedListResp.Body.Close() }()
	if blockedListResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /dashboard/api/anomalies/blocked, got %d", blockedListResp.StatusCode)
	}
	var blockedEntries []map[string]any
	if err := json.NewDecoder(blockedListResp.Body).Decode(&blockedEntries); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	found := false
	for _, e := range blockedEntries {
		if e["identity"] == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected alice in /dashboard/api/anomalies/blocked, got %+v", blockedEntries)
	}
}

// TestServeEndToEnd_MLScoreAutoBlock_BlockExpiresAndIdentityRecovers proves
// the block installed by auto_block is time-bounded, not permanent: once
// block_duration_seconds elapses, BlockChecker.Check reads the same
// identity as allowed again (see auto_block.go's Check doc comment -- a
// block whose TTL has passed reads as "not blocked" purely by comparing
// against wall-clock time, no separate expiry/GC step required for the
// read path). block_duration_seconds is kept short (2s) so this test
// doesn't need a long sleep, matching this file's fast-window style
// elsewhere (e.g. TestServeEndToEnd_AnomalyDetectionRateSpike's 3s window).
func TestServeEndToEnd_MLScoreAutoBlock_BlockExpiresAndIdentityRecovers(t *testing.T) {
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
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 2   # below the example config's 5: this test's baseline windows are 2-3 calls, which a floor of 5 would skip entirely
  auto_block:
    enabled: true
    score_threshold: 3.0
    block_duration_seconds: 2`, anomalyPath))

	doCall := func(identity, tool string) {
		resp := postToolCall(t, listenAddr, identity, tool)
		_ = resp.Body.Close()
	}

	// Same baseline-then-outlier shape as TestServeEndToEnd_MLScoreAutoBlock
	// -- 10 non-identical baseline windows (two more than
	// minSamplesForZScore, for the same margin reasoning documented there)
	// so onlineStat.ZScore() has a non-zero variance to compare the outlier
	// window against, then one wild outlier window of many distinct,
	// rapid-fire tool calls.
	for i := 0; i < 5; i++ {
		doCall("alice", "read_file")
		doCall("alice", "read_file")
		time.Sleep(3100 * time.Millisecond)
		doCall("alice", "read_file")
		doCall("alice", "list_dir")
		doCall("alice", "list_dir")
		time.Sleep(3100 * time.Millisecond)
	}

	for i := 0; i < 30; i++ {
		doCall("alice", fmt.Sprintf("tool_%d", i))
	}
	time.Sleep(3100 * time.Millisecond)
	doCall("alice", "read_file")

	data, err := os.ReadFile(anomalyPath)
	if err != nil {
		t.Fatalf("failed to read anomaly output: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Contains(data, []byte(`"kind":"ml_score"`)) {
		t.Fatalf("expected an ml_score anomaly line in %s, got: %s", anomalyPath, data)
	}
	// Name the feature that must have driven the score, not just "some
	// ml_score anomaly fired": asserting the driving feature catches a
	// regression that still fires an anomaly but for the wrong reason. The
	// outlier window is 30 calls over 30 distinct tools against a baseline
	// alternating 2-3 calls over 1-2 distinct tools, so both volumetric
	// features fire hard and tool_diversity leads by a nose. This config's
	// min_calls of 2 puts both of them in the sub-quantum zone zCount's count
	// floor exists for -- distinct-tool count has baseline mean 1.5 (relative
	// floor 0.15*1.5 = 0.225) and call rate mean 2.5 (relative floor 0.375),
	// both well under one whole tool/call -- so each is floored at
	// max(1.0, sqrt(mean)): 1.2247 for diversity and 1.5811 for rate. The
	// outlier scores z_diversity = (30-1.5)/1.2247 = 23.27, comfortably past
	// call_rate's z_rate = (30-2.5)/1.5811 = 17.39. Neither depends on the raw
	// sample stddev at all, which makes this assertion more deterministic than
	// the pre-round-10 54.1-vs-52.2 it replaces, not less -- and round 11's
	// sqrt(mean) floor widens diversity's lead rather than narrowing it, since
	// the smaller-mean feature gets the smaller divisor. Flooring only one of
	// the two would invert the result: with diversity floored and call_rate
	// not, call_rate's un-floored 52.2 wins on an artifact. 30 distinct tools from an identity that normally
	// touches 1-2 is textbook enumeration, so diversity leading is the
	// right answer here -- it took the lead only once that feature was
	// scored as a raw distinct-tool count instead of distinct/total, a
	// ratio that pinned this window to its own 1.0 ceiling (z = 4.7) no
	// matter how many tools the burst actually swept.
	if !bytes.Contains(data, []byte(`(driving feature: tool_diversity)`)) {
		t.Fatalf("expected the ml_score anomaly to be driven by tool_diversity in %s, got: %s", anomalyPath, data)
	}

	blockedResp := postToolCall(t, listenAddr, "alice", "read_file")
	defer func() { _ = blockedResp.Body.Close() }()
	if blockedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for the auto-blocked identity, got %d (stderr: %s)", blockedResp.StatusCode, stderr.String())
	}

	// Wait out block_duration_seconds (2s) plus margin, then confirm the
	// same identity that was just rejected succeeds again -- the block
	// expired rather than persisting indefinitely.
	time.Sleep(2500 * time.Millisecond)

	recoveredResp := postToolCall(t, listenAddr, "alice", "read_file")
	defer func() { _ = recoveredResp.Body.Close() }()
	if recoveredResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice after block_duration_seconds elapsed, got %d (stderr: %s)", recoveredResp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_AutoBlockOff_BlockedListRouteReturns404 proves the
// dashboard's /dashboard/api/anomalies/blocked route answers 404 -- not a
// panic, not an empty-but-200 list -- when anomaly_detection and web_ui are
// both on but auto_block is left off (unset from config entirely here).
// This is the exact combination the typed-nil bug Task 7 fixed would have
// broken: main.go only assigns dashboardadapter.BlockedSource when
// blockChecker != nil (a real *BlockChecker, never a nil one wrapped in
// the interface), so h.blocked stays a true nil interface and
// handleBlocked's "h.blocked == nil" guard in
// internal/features/dashboard/adapter/handler.go correctly answers 404
// instead of dereferencing a nil BlockChecker. A real proxied call is
// made first so the "auto_block off" path is exercised under live
// traffic, not just checked against an idle server.
func TestServeEndToEnd_AutoBlockOff_BlockedListRouteReturns404(t *testing.T) {
	dir := t.TempDir()
	anomalyPath := filepath.Join(dir, "anomaly.jsonl")

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
default: allow
`, fmt.Sprintf(`features:
  web_ui: true
  anomaly_detection: true
anomaly:
  output: "%s"
  window_seconds: 2`, anomalyPath))

	callResp := postToolCall(t, listenAddr, "alice", "read_file")
	defer func() { _ = callResp.Body.Close() }()
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a normal call with auto_block off, got %d (stderr: %s)", callResp.StatusCode, stderr.String())
	}

	resp, err := http.Get("http://" + listenAddr + "/dashboard/api/anomalies/blocked")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 from /dashboard/api/anomalies/blocked when auto_block is off, got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_DefaultConfigNoiseAndDisabledCredentialsRoutesReturn404
// closes a gap the I1/I4 unit tests (main_test.go) left open: those tests
// hand-build their own extraRoutes map and call buildTopHandler directly,
// which proves routeOrNotFound/noiseRouteHandler work as a MECHANISM but
// never confirms runServe actually wires them into a real startup path.
// This starts a real "wardline serve" subprocess with a bare-default
// config (no web_ui, no credential_issuance, no special flags) and
// confirms both wiring points survive real startup: a generic-noise path
// returns a clean 404 instead of falling through to the proxy catch-all,
// and so does a disabled /credentials/* route.
func TestServeEndToEnd_DefaultConfigNoiseAndDisabledCredentialsRoutesReturn404(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
default: allow
`, "")

	robotsResp, err := http.Get("http://" + listenAddr + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = robotsResp.Body.Close()
	if robotsResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected a clean 404 (routed to noiseRouteHandler, never reaching the proxy) for GET /robots.txt on a default-config real instance, got %d (stderr: %s)", robotsResp.StatusCode, stderr.String())
	}

	tokenResp := postCredentialsToken(t, listenAddr, "any-secret")
	_ = tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected a clean 404 (routed to routeOrNotFound, never reaching the proxy) for POST /credentials/token with credential_issuance off on a default-config real instance, got %d (stderr: %s)", tokenResp.StatusCode, stderr.String())
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

// TestValidateConfigEndToEnd_SigningKeyFileIgnoredWhenCredentialIssuanceOff
// proves validate-config's signing-key check is gated on
// features.credential_issuance, matching the field's own runtime
// behavior (main.go only loads it inside the credentialIssuanceEnabled
// block) -- a stale signing_key_file left in a config template for a
// deployment where the feature is off must not fail validation.
func TestValidateConfigEndToEnd_SigningKeyFileIgnoredWhenCredentialIssuanceOff(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A deliberately invalid/nonexistent signing_key_file -- if this
	// were still checked unconditionally, validate-config would fail.
	config := fmt.Sprintf(`listen: ":8080"
upstream: "http://localhost:9000"
policy_file: %q
audit:
  output: stdout
credential:
  signing_key_file: %q
`, policyPath, filepath.Join(dir, "does-not-exist.pem"))
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
		t.Fatalf("validate-config must not check signing_key_file when credential_issuance is off, got: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("config file is valid")) {
		t.Fatalf("expected a valid verdict, got: %s", out)
	}
}

// TestValidateConfigEndToEnd_MTLSBadCredentialsFileFailsHard proves
// validate-config hard-fails (non-zero exit) when bootstrap_source: mtls
// is configured with a credentials.yaml that doesn't parse -- the same
// "local file read, no network call to fail softly on" reasoning
// runValidateConfig documents for its LoadMTLSBootstrapper call, unlike
// the oidc block right above it in main.go, which only warns on a
// possibly-transient JWKS failure.
func TestValidateConfigEndToEnd_MTLSBadCredentialsFileFailsHard(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// A missing credentials.yaml -- LoadMTLSBootstrapper's os.ReadFile
	// fails outright, the simplest way to hit the "doesn't parse" case
	// without needing a malformed-YAML fixture too.
	missingCredentialsPath := filepath.Join(dir, "does-not-exist.yaml")
	config := fmt.Sprintf(`listen: ":8080"
upstream: "http://localhost:9000"
policy_file: %q
audit:
  output: stdout
features:
  credential_issuance: true
credential:
  identities_file: %q
  bootstrap_source: "mtls"
  mtls:
    header: "X-Wardline-Verified-Spiffe-Id"
`, policyPath, missingCredentialsPath)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	out, err := exec.Command(binPath, "validate-config", "--config", configPath).CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit for bootstrap_source: mtls with a missing credentials file, got: %s", out)
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
	if !bytes.Contains(out, []byte("finalize output file")) {
		t.Fatalf("expected the rename-failure log message, got: %s", out)
	}
	// The atomic write uses os.CreateTemp(dir, ".evidence-*.tar.gz.tmp") in
	// outputDir's parent directory (same atomic-write pattern
	// policyadapter.WriteFile/config.WriteBudgetSection already
	// established) -- a rename failure must still clean that temp file up,
	// not leave it behind under a random name.
	leftover, err := filepath.Glob(filepath.Join(dir, ".evidence-*.tar.gz.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftover) != 0 {
		t.Fatalf("expected no leftover temp files after a rename failure, found: %v", leftover)
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

// TestVerifyEvidenceEndToEnd_FullLifecycle exercises generate-signing-key
// -> export-evidence -sign-key -> verify-evidence as three real
// subprocess invocations of the compiled binary -- proving a genuine
// signed bundle verifies successfully, an unsigned bundle is reported as
// unsigned (not silently "passed"), and a tampered signed bundle fails
// verification with a non-zero exit -- the whole point of shipping
// verify-evidence as a distinct command from sha256sum -c.
func TestVerifyEvidenceEndToEnd_FullLifecycle(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")

	if err := os.WriteFile(policyPath, []byte("rules: []\ndefault: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "127.0.0.1:0"
upstream: "http://127.0.0.1:1"
policy_file: "%s"
audit:
  output: "%s"
`, policyPath, auditPath)), 0644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	privKeyPath := filepath.Join(dir, "priv.pem")
	pubKeyPath := filepath.Join(dir, "pub.pem")
	genOut, err := exec.Command(binPath, "generate-signing-key",
		"-private-key", privKeyPath, "-public-key", pubKeyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("generate-signing-key failed: %v\n%s", err, genOut)
	}

	signedPath := filepath.Join(dir, "signed.tar.gz")
	exportOut, err := exec.Command(binPath, "export-evidence",
		"--config", configPath, "-from", "2020-01-01T00:00:00Z", "-to", "2030-01-01T00:00:00Z",
		"-output", signedPath, "-sign-key", privKeyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("export-evidence -sign-key failed: %v\n%s", err, exportOut)
	}

	unsignedPath := filepath.Join(dir, "unsigned.tar.gz")
	if out, err := exec.Command(binPath, "export-evidence",
		"--config", configPath, "-from", "2020-01-01T00:00:00Z", "-to", "2030-01-01T00:00:00Z",
		"-output", unsignedPath).CombinedOutput(); err != nil {
		t.Fatalf("export-evidence (unsigned) failed: %v\n%s", err, out)
	}

	// A genuinely signed bundle verifies cleanly.
	verifyOut, err := exec.Command(binPath, "verify-evidence",
		"-bundle", signedPath, "-public-key", pubKeyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("expected verify-evidence to succeed on a genuinely signed bundle, got error: %v\n%s", err, verifyOut)
	}
	if !bytes.Contains(verifyOut, []byte("signature verified")) {
		t.Errorf("expected a signature-verified confirmation, got: %s", verifyOut)
	}

	// Integrity-only check (no -public-key) still passes for an unsigned bundle.
	unsignedVerifyOut, err := exec.Command(binPath, "verify-evidence", "-bundle", unsignedPath).CombinedOutput()
	if err != nil {
		t.Fatalf("expected integrity-only verify to succeed on an unsigned bundle, got error: %v\n%s", err, unsignedVerifyOut)
	}

	// Asking to verify a signature against an unsigned bundle is a hard failure, not a silent pass.
	missingSigCmd := exec.Command(binPath, "verify-evidence", "-bundle", unsignedPath, "-public-key", pubKeyPath)
	missingSigOut, err := missingSigCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify-evidence to fail when -public-key is given but the bundle isn't signed, got no error; output: %s", missingSigOut)
	}
	if !bytes.Contains(missingSigOut, []byte("not signed")) {
		t.Errorf("expected a clear \"not signed\" message, got: %s", missingSigOut)
	}

	// Tampering with the signed bundle after the fact must fail
	// verification -- re-append a byte-corrupted copy is unnecessary;
	// simplest real tamper is truncating the file, which breaks the
	// gzip/tar stream and must surface as a read error, not a false pass.
	tamperedPath := filepath.Join(dir, "tampered.tar.gz")
	signedBytes, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(signedBytes) < 100 {
		t.Fatalf("signed bundle unexpectedly small (%d bytes), can't safely truncate for the tamper test", len(signedBytes))
	}
	if err := os.WriteFile(tamperedPath, signedBytes[:len(signedBytes)-50], 0644); err != nil {
		t.Fatal(err)
	}
	tamperedOut, err := exec.Command(binPath, "verify-evidence",
		"-bundle", tamperedPath, "-public-key", pubKeyPath).CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify-evidence to fail on a truncated/corrupted bundle, got no error; output: %s", tamperedOut)
	}
}

// TestLogRetentionEndToEnd_PurgesOldAuditEntriesOnAShortTicker starts a
// real serve subprocess with features.log_retention on and a 1-second
// retention.check_interval_seconds against a file pre-seeded with one
// entry from 2020 (older than the 1-day retention window) and one from
// "now" (younger) -- proves the background job actually runs on its
// configured cadence and purges only what it should.
func TestLogRetentionEndToEnd_PurgesOldAuditEntriesOnAShortTicker(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")

	seed := `{"timestamp":"2020-01-01T00:00:00Z","identity":"ancient","tenant":"default","tool":"read_file","decision":"allow","latency_ms":1}
{"timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `","identity":"recent","tenant":"default","tool":"read_file","decision":"allow","latency_ms":1}
`
	if err := os.WriteFile(auditPath, []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("rules: []\ndefault: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	listenAddr := reserveAddr(t)

	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: "%s"
  retention_days: 1
features:
  log_retention: true
retention:
  check_interval_seconds: 1
`, listenAddr, upstream.URL, policyPath, auditPath)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	var stderr safeBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForListener(t, listenAddr)

	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"identity":"ancient"`) {
			if !strings.Contains(string(data), `"identity":"recent"`) {
				t.Fatalf("expected the recent entry to survive retention, got:\n%s", data)
			}
			break // purged -- success
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for retention to purge the ancient entry (stderr: %s)", stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestScheduledExportEndToEnd_ProducesABundleWithoutAnyCLIInvocation
// starts a real serve subprocess with features.compliance_scheduled_export
// on and a 1-second interval, and proves a bundle file appears in the
// configured output directory purely from the background ticker -- no
// export-evidence CLI call is made by this test.
func TestScheduledExportEndToEnd_ProducesABundleWithoutAnyCLIInvocation(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")
	outputDir := filepath.Join(dir, "evidence")

	if err := os.WriteFile(auditPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("rules: []\ndefault: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	listenAddr := reserveAddr(t)

	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: "%s"
features:
  compliance_scheduled_export: true
compliance:
  scheduled_export_interval_seconds: 1
  scheduled_export_output_dir: "%s"
`, listenAddr, upstream.URL, policyPath, auditPath, outputDir)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	var stderr safeBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForListener(t, listenAddr)

	deadline := time.Now().Add(10 * time.Second)
	for {
		entries, err := os.ReadDir(outputDir)
		if err == nil && len(entries) > 0 {
			break // a scheduled bundle appeared -- success
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a scheduled export bundle to appear in %s (stderr: %s)", outputDir, stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestServeEndToEnd_DashboardComplianceQuery_ReflectsRealProxiedCalls
// proves GET /dashboard/api/compliance is a real live query against a
// real running server: an allow and a deny made through the proxy both
// show up in the returned Manifest's counts, with zero CLI invocation.
func TestServeEndToEnd_DashboardComplianceQuery_ReflectsRealProxiedCalls(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	binPath := filepath.Join(dir, "wardline")

	if err := os.WriteFile(auditPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`
rules:
  - identity: "agent-1"
    tool: "read_file"
    effect: allow
default: deny
`), 0644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)
	listenAddr := reserveAddr(t)

	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: "%s"
features:
  web_ui: true
`, listenAddr, upstream.URL, policyPath, auditPath)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	var stderr safeBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForListener(t, listenAddr)

	before := time.Now().Add(-time.Minute)
	allowResp := postToolCall(t, listenAddr, "agent-1", "read_file")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (stderr: %s)", allowResp.StatusCode, stderr.String())
	}
	denyResp := postToolCall(t, listenAddr, "agent-1", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (stderr: %s)", denyResp.StatusCode, stderr.String())
	}
	after := time.Now().Add(time.Minute)

	url := fmt.Sprintf("http://%s/dashboard/api/compliance?from=%s&to=%s",
		listenAddr, before.UTC().Format(time.RFC3339), after.UTC().Format(time.RFC3339))
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("dashboard compliance API failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s (stderr: %s)", resp.StatusCode, body, stderr.String())
	}
	var manifest struct {
		AuditEntryCount     int            `json:"audit_entry_count"`
		AuditDecisionCounts map[string]int `json:"audit_decision_counts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		t.Fatalf("invalid manifest JSON: %v", err)
	}
	if manifest.AuditEntryCount != 2 {
		t.Errorf("expected 2 audit entries, got %d", manifest.AuditEntryCount)
	}
	if manifest.AuditDecisionCounts["allow"] != 1 || manifest.AuditDecisionCounts["deny"] != 1 {
		t.Errorf("unexpected decision counts: %+v", manifest.AuditDecisionCounts)
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

// TestPolicyPackEndToEnd_OPAVariantIsEnforcedByRealServe is
// TestPolicyPackEndToEnd_InstalledPackIsEnforcedByRealServe's OPA-backend
// analog: installs read-only-single-identity-opa, renames its placeholder
// identity to a real one (real OPA packs, unlike the YAML ones, ship with
// the placeholder as literal Rego source text -- renaming means editing
// the installed file directly, exactly as the pack's own instructions
// say to), points a real serve at it with policy_backend: opa, and proves
// the installed Rego is genuinely enforced.
func TestPolicyPackEndToEnd_OPAVariantIsEnforcedByRealServe(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "installed-policy.rego")

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	installCmd := exec.Command(binPath, "policy-pack", "install", "read-only-single-identity-opa", "-output", policyPath)
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("policy-pack install failed: %v\n%s", err, out)
	}
	installed, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("expected the installed policy file to exist: %v", err)
	}
	renamed := strings.ReplaceAll(string(installed), "REPLACE_WITH_YOUR_IDENTITY", "agent-real")
	if err := os.WriteFile(policyPath, []byte(renamed), 0644); err != nil {
		t.Fatal(err)
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
policy_backend: opa
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

	allowedResp := postToolCall(t, realListenAddr, "agent-real", "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the pack's allowed tool, got %d (stderr: %s)", allowedResp.StatusCode, serveStderr.String())
	}
	deniedResp := postToolCall(t, realListenAddr, "agent-real", "delete_file")
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a tool the pack doesn't allow, got %d (stderr: %s)", deniedResp.StatusCode, serveStderr.String())
	}
	otherIdentityResp := postToolCall(t, realListenAddr, "someone-else", "read_file")
	if otherIdentityResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a different identity (pack's default deny), got %d (stderr: %s)", otherIdentityResp.StatusCode, serveStderr.String())
	}
}

// TestPolicyPackEndToEnd_PacksDirMergesWithEmbeddedCatalog proves
// -packs-dir is real end-to-end: a real "policy-pack list -packs-dir
// <tmp>" subprocess lists both a known embedded pack name and a custom
// one placed in the operator-owned directory.
func TestPolicyPackEndToEnd_PacksDirMergesWithEmbeddedCatalog(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	packsDir := filepath.Join(dir, "my-packs")
	customPackDir := filepath.Join(packsDir, "acme-baseline")
	if err := os.MkdirAll(customPackDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(customPackDir, "pack.yaml"), []byte("name: acme-baseline\ndescription: \"acme's own starting policy\"\nbackend: yaml\npolicy_file: policy.yaml\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(customPackDir, "policy.yaml"), []byte("default: deny\n"), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	out, err := exec.Command(binPath, "policy-pack", "list", "-packs-dir", packsDir).CombinedOutput()
	if err != nil {
		t.Fatalf("policy-pack list -packs-dir failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "deny-all-baseline") {
		t.Errorf("expected the embedded catalog to still be listed alongside -packs-dir, got:\n%s", out)
	}
	if !strings.Contains(string(out), "acme-baseline") {
		t.Errorf("expected the custom -packs-dir pack to be listed, got:\n%s", out)
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
// TestHAEndToEnd_TwoReplicasShareAutoBlock is the HA proof for the
// distributed auto-block: two real replicas share one Postgres DSN with
// auto_block on. A block written into the shared blocked_identities table
// (simulating replica A's detector having auto-blocked an identity --
// the detector's block-trigger logic is unit-tested separately; the e2e
// gap this closes is "does a block written by one replica take effect on
// another") causes replica B's proxy to deny that identity's next call
// with 403, while a different identity is unaffected.
func TestHAEndToEnd_TwoReplicasShareAutoBlock(t *testing.T) {
	dsn := testDSN(t)
	dropBlockedIdentitiesTableE2E(t, dsn)

	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "policy.yaml")
	anomalyPath := filepath.Join(dir, "anomaly.jsonl")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	if err := os.WriteFile(policyPath, []byte(`default: allow`), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	addrA := reserveAddr(t)
	addrB := reserveAddr(t)
	startReplica := func(listenAddr string) *safeBuffer {
		configPath := filepath.Join(dir, listenAddr+"-wardline.yaml")
		if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
features:
  anomaly_detection: true
  postgres_storage: true
anomaly:
  output: "%s"
  window_seconds: 3
  gc_interval_seconds: 1800
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 2
  auto_block:
    enabled: true
    score_threshold: 3.0
    block_duration_seconds: 3600
audit:
  postgres_dsn: "%s"
`, listenAddr, upstream.URL, policyPath, anomalyPath, dsn)), 0644); err != nil {
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
		return stderr
	}

	// Start both replicas -- the first to start creates the shared
	// blocked_identities table via CREATE TABLE IF NOT EXISTS.
	_ = startReplica(addrA)
	stderrB := startReplica(addrB)

	// Simulate replica A's detector having blocked the identity: write the
	// block row directly into the shared table both replicas connect to.
	blockDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open shared db: %v", err)
	}
	defer func() { _ = blockDB.Close() }()
	// Key format matches internal/platform/tenant.Key exactly:
	// len(tenant) + ":" + tenant + identity. Computed inline (rather than
	// importing the internal package into this external test) so a drift
	// in that format is caught by this test failing, which is the point.
	blockKey := fmt.Sprintf("%d:%s%s", len("default"), "default", "blocked-agent")
	if _, err := blockDB.Exec(
		`INSERT INTO blocked_identities (key, tenant, identity, reason, blocked_since, blocked_until) VALUES ($1, $2, $3, $4, $5, $6)`,
		blockKey, "default", "blocked-agent", "ml_score anomaly on replica A", time.Now(), time.Now().Add(time.Hour),
	); err != nil {
		t.Fatalf("insert shared block row: %v", err)
	}

	// Replica B denies the blocked identity's next call.
	blockedResp := postToolCall(t, addrB, "blocked-agent", "read_file")
	if blockedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected replica B to honor a block written by replica A (shared postgres), got %d (stderr: %s)", blockedResp.StatusCode, stderrB.String())
	}

	// A different identity is unaffected.
	allowedResp := postToolCall(t, addrB, "other-agent", "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected an unblocked identity to be allowed on replica B, got %d (stderr: %s)", allowedResp.StatusCode, stderrB.String())
	}
}

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

// genRSAKeyPairE2E shells out to openssl (same tool TestHAEndToEnd already
// depends on) to generate a real RSA private key plus its matching PKIX
// "PUBLIC KEY" PEM -- the two shapes adapter.ParsePrivateKeyPEM and
// adapter.ParsePublicKeyPEM expect, respectively.
func genRSAKeyPairE2E(t *testing.T, dir, name string) (privPath, pubPath string) {
	t.Helper()
	privPath = filepath.Join(dir, name+"-private.pem")
	pubPath = filepath.Join(dir, name+"-public.pem")
	if out, err := exec.Command("openssl", "genrsa", "-out", privPath, "2048").CombinedOutput(); err != nil {
		t.Fatalf("generate %s private key: %v\n%s", name, err, out)
	}
	if out, err := exec.Command("openssl", "rsa", "-in", privPath, "-pubout", "-out", pubPath).CombinedOutput(); err != nil {
		t.Fatalf("derive %s public key: %v\n%s", name, err, out)
	}
	return privPath, pubPath
}

// waitForCorrelatedAlertE2E polls addr's /dashboard/api/federation/correlated
// until a CorrelatedAlert whose InstanceIDs cover every id in wantIDs
// appears, or fails the test after a generous deadline -- correlation is
// necessarily eventually-consistent (it depends on both instances'
// publish tickers firing and a real HTTP round trip between them), so
// this follows the same poll-until-true shape as this file's other
// eventually-consistent assertions (e.g. TestServeEndToEnd_OTLPExport's
// collector poll) rather than a fixed sleep.
func waitForCorrelatedAlertE2E(t *testing.T, addr string, wantIDs []string, stderrA, stderrB *safeBuffer) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/dashboard/api/federation/correlated?after=0&limit=50")
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				// Field name matches dashboard/domain.CorrelatedAlertEntry's
				// snake_case wire shape, not the federation usecase type's
				// Go-cased fields -- see dashboard/adapter.handleFederationCorrelated.
				var entries []struct {
					InstanceIDs []string `json:"instance_ids"`
				}
				if decErr := json.NewDecoder(resp.Body).Decode(&entries); decErr == nil {
					for _, e := range entries {
						seen := make(map[string]bool, len(e.InstanceIDs))
						for _, id := range e.InstanceIDs {
							seen[id] = true
						}
						allPresent := true
						for _, want := range wantIDs {
							if !seen[want] {
								allPresent = false
								break
							}
						}
						if allPresent {
							_ = resp.Body.Close()
							return
						}
					}
				}
			}
			_ = resp.Body.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no correlated alert covering instance IDs %v ever appeared at %s within deadline\nstderr A: %s\nstderr B: %s", wantIDs, addr, stderrA.String(), stderrB.String())
}

// TestE2E_FederationCorrelatesAcrossInstances is the whole federation
// feature's end-to-end proof point: two real wardline serve subprocesses
// (instance-a, instance-b), each with its own RSA signing key but a
// shared HMAC secret and a peers.yaml naming the other by its real
// listen address, independently trip their own local rate-spike
// detector for the SAME identity, publish their pseudonymized summaries
// to each other over a real signed HTTP POST, and each ends up with a
// CorrelatedAlert naming both instances via its own
// /dashboard/api/federation/correlated.
//
// This test is self-contained (does not reuse startWardline), following
// the same pattern TestHAEndToEnd_TwoReplicasShareSigningKeyAndRevocation
// already established for multi-process e2e tests: startWardline calls
// reserveAddr(t) internally and doesn't return the address or temp dir
// it used, so a caller can't learn instance A's real listen address
// before starting it -- but that address has to be baked into instance
// B's peers.yaml (and vice versa) before either process starts. Building
// the binary and writing each instance's config directly (as
// TestHAEndToEnd and TestExportEvidenceEndToEnd_RealBundleFromRealBinary
// already do) sidesteps the chicken-and-egg problem entirely, without
// changing startWardline's signature or behavior for its ~25 other
// callers.
func TestE2E_FederationCorrelatesAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "policy.yaml")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}

	privA, pubA := genRSAKeyPairE2E(t, dir, "instance-a")
	privB, pubB := genRSAKeyPairE2E(t, dir, "instance-b")
	sharedSecretPath := filepath.Join(dir, "shared-secret")
	if err := os.WriteFile(sharedSecretPath, []byte("federation-e2e-shared-hmac-secret"), 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	addrA := reserveAddr(t)
	addrB := reserveAddr(t)

	peersAPath := filepath.Join(dir, "peers-a.yaml")
	if err := os.WriteFile(peersAPath, []byte(fmt.Sprintf(`
peers:
  - id: "instance-b"
    endpoint: "http://%s/federation/summaries"
    public_key_file: "%s"
`, addrB, pubB)), 0644); err != nil {
		t.Fatal(err)
	}
	peersBPath := filepath.Join(dir, "peers-b.yaml")
	if err := os.WriteFile(peersBPath, []byte(fmt.Sprintf(`
peers:
  - id: "instance-a"
    endpoint: "http://%s/federation/summaries"
    public_key_file: "%s"
`, addrA, pubA)), 0644); err != nil {
		t.Fatal(err)
	}

	buildConfig := func(listenAddr, instanceID, anomalyPath, signingKeyPath, peersPath string) string {
		return fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: stdout
features:
  web_ui: true
  anomaly_detection: true
  federation: true
anomaly:
  output: "%s"
  window_seconds: 3
  rate_spike:
    enabled: true
    rate_multiplier: 2.0
    min_calls: 5
federation:
  instance_id: "%s"
  peers_file: "%s"
  signing_key_file: "%s"
  shared_secret_file: "%s"
  publish_interval_seconds: 1
  min_instances_for_correlation: 2
  correlation_window_seconds: 300
  gc_interval_seconds: 600
`, listenAddr, upstream.URL, policyPath, anomalyPath, instanceID, peersPath, signingKeyPath, sharedSecretPath)
	}

	configAPath := filepath.Join(dir, "wardline-a.yaml")
	if err := os.WriteFile(configAPath, []byte(buildConfig(addrA, "instance-a", filepath.Join(dir, "anomaly-a.jsonl"), privA, peersAPath)), 0644); err != nil {
		t.Fatal(err)
	}
	configBPath := filepath.Join(dir, "wardline-b.yaml")
	if err := os.WriteFile(configBPath, []byte(buildConfig(addrB, "instance-b", filepath.Join(dir, "anomaly-b.jsonl"), privB, peersBPath)), 0644); err != nil {
		t.Fatal(err)
	}

	startInstance := func(listenAddr, configPath string) *safeBuffer {
		cmd := exec.Command(binPath, "serve", "--config", configPath)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start instance at %s: %v", listenAddr, err)
		}
		waiter := waitFor(cmd)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			<-waiter.done
		})
		waitForServer(t, "http://"+listenAddr)
		return stderr
	}

	stderrA := startInstance(addrA, configAPath)
	stderrB := startInstance(addrB, configBPath)

	doCall := func(addr, identity string) {
		resp := postToolCall(t, addr, identity, "read_file")
		_ = resp.Body.Close()
	}

	// Same burst shape as TestServeEndToEnd_AnomalyDetectionRateSpike: 5
	// baseline calls, sleep past the 3s window, then 11 calls -- above
	// both 5*2.0=10 and the min-calls floor -- driven independently
	// against each instance so each trips its own local rate-spike
	// detector for the same identity.
	burst := func(addr string) {
		for i := 0; i < 5; i++ {
			doCall(addr, "alice")
		}
		time.Sleep(3100 * time.Millisecond)
		for i := 0; i < 11; i++ {
			doCall(addr, "alice")
		}
	}
	burst(addrA)
	burst(addrB)

	// Each instance's own Publisher feeds its local detection into its
	// own Correlator every publish_interval_seconds tick, and pushes a
	// signed summary batch to the other instance's /federation/summaries
	// -- so each side eventually has a CorrelatedAlert naming both
	// instance-a and instance-b.
	waitForCorrelatedAlertE2E(t, addrA, []string{"instance-a", "instance-b"}, stderrA, stderrB)
	waitForCorrelatedAlertE2E(t, addrB, []string{"instance-a", "instance-b"}, stderrA, stderrB)
}

// TestE2E_FederationDisabledBlocksSummariesAndCorrelatedAPI proves the
// federation feature flag actually gates both its inbound HTTP surfaces
// when off: /federation/summaries answers a clean 404 (registered
// unconditionally via routeOrNotFound -- see main.go and I1 in the final
// whole-branch review fix wave -- rather than falling through to the "/"
// proxy catch-all, which used to reject the non-JSON-RPC body with 400
// and, worse, write a spurious audit-log "error" entry for every request;
// this test used to assert that old, buggy fallthrough-to-proxy behavior
// directly), and /dashboard/api/federation/correlated answers 404 (the
// same documented nil-FederationSource posture already covered for
// anomalies by TestServeEndToEnd_AnomalyDetectionOffProducesNoOutput).
func TestE2E_FederationDisabledBlocksSummariesAndCorrelatedAPI(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "policy.yaml")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	if err := os.WriteFile(policyPath, []byte("default: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	addrA := reserveAddr(t)
	addrB := reserveAddr(t)

	buildConfig := func(listenAddr string) string {
		return fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
audit:
  output: stdout
features:
  web_ui: true
  federation: false
`, listenAddr, upstream.URL, policyPath)
	}

	configAPath := filepath.Join(dir, "wardline-a.yaml")
	if err := os.WriteFile(configAPath, []byte(buildConfig(addrA)), 0644); err != nil {
		t.Fatal(err)
	}
	configBPath := filepath.Join(dir, "wardline-b.yaml")
	if err := os.WriteFile(configBPath, []byte(buildConfig(addrB)), 0644); err != nil {
		t.Fatal(err)
	}

	startInstance := func(listenAddr, configPath string) *safeBuffer {
		cmd := exec.Command(binPath, "serve", "--config", configPath)
		stderr := &safeBuffer{}
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start instance at %s: %v", listenAddr, err)
		}
		waiter := waitFor(cmd)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			<-waiter.done
		})
		waitForServer(t, "http://"+listenAddr)
		return stderr
	}

	stderrA := startInstance(addrA, configAPath)
	stderrB := startInstance(addrB, configBPath)

	for _, addr := range []string{addrA, addrB} {
		summariesResp, err := http.Get("http://" + addr + "/federation/summaries")
		if err != nil {
			t.Fatalf("GET /federation/summaries at %s: %v", addr, err)
		}
		_ = summariesResp.Body.Close()
		if summariesResp.StatusCode != http.StatusNotFound {
			t.Errorf("expected a clean 404 (routed to routeOrNotFound, never reaching the proxy) for /federation/summaries at %s when federation is off, got %d (stderr A: %s, stderr B: %s)", addr, summariesResp.StatusCode, stderrA.String(), stderrB.String())
		}

		correlatedResp, err := http.Get("http://" + addr + "/dashboard/api/federation/correlated")
		if err != nil {
			t.Fatalf("GET /dashboard/api/federation/correlated at %s: %v", addr, err)
		}
		_ = correlatedResp.Body.Close()
		if correlatedResp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 from /dashboard/api/federation/correlated at %s when federation is off, got %d", addr, correlatedResp.StatusCode)
		}
	}
}

// testSchema isolates this package's real-Postgres e2e tests from the
// audit and credential adapter packages' own Postgres tests --
// internal/features/audit/adapter and internal/features/credential/adapter
// each run against the same WARDLINE_TEST_POSTGRES_DSN-pointed database,
// and go test ./... schedules different packages' test binaries
// concurrently, so a DROP TABLE from one package could otherwise race a
// live query/insert from another against tables of the same name in the
// shared "public" schema.
const testSchema = "wardline_test_e2e"

// testDSN returns the DSN every real-Postgres test in this package
// should use, skipping the test if none is configured. search_path is
// pinned to testSchema so every table created by a real wardline serve
// subprocess started with this DSN (audit.postgres_dsn or the
// credential revoker's DSN) stays confined to it, same as
// audit/adapter and credential/adapter's own testDSN helpers.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open to create test schema: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + testSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + testSchema
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
}

func dropAuditEntriesTableE2E(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_entries`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func dropBlockedIdentitiesTableE2E(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS blocked_identities`); err != nil {
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

	// After SetDraining(true), main.go holds the listener open for
	// readinessDrainWindow (see its doc comment) before srv.Shutdown starts
	// refusing new connections -- a bounded window in which a *new*
	// connection reliably reads a 503, so this test is deterministic rather
	// than racing a few-scheduler-ticks window (which flaked under -race/CI
	// load). The 2ms poll below lands dozens of attempts inside that window.
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

// reloadResponse mirrors the wire shape of reload.ReloadResult
// (internal/platform/reload/coordinator.go) -- no json tags there either,
// so this decodes the Go field names verbatim, the same convention
// dashboardAuditEntry (e2e_tenant_isolation_test.go) already uses for
// dashboard/domain.LiveEntry.
type reloadResponse struct {
	Domain    string
	OK        bool
	Error     string
	AppliedBy string
}

// postReload POSTs to /dashboard/api/reload/{domain} as identity (via
// X-Wardline-Identity, resolved by the default HeaderIdentity
// authenticator -- none of the reload tests enable credential_issuance)
// and decodes the JSON reload.ReloadResult body. handleReload always
// answers 200 with OK true/false in the body for a recognized domain --
// only an authorization failure (missing config:edit) produces a non-200 --
// so this fails the test on a non-200 (an auth/wiring bug) but leaves
// interpreting OK/Error to the caller.
func postReload(t *testing.T, listenAddr, domain, identity string) reloadResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/dashboard/api/reload/"+domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reload %s as %s: expected 200, got %d: %s", domain, identity, resp.StatusCode, b)
	}
	var result reloadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("invalid reload response: %v", err)
	}
	return result
}

// dashboardStatusCode GETs /dashboard/api/status as identity, returning
// just the status code -- used by the RBAC reload test as a cheap
// "does this identity currently hold dashboard:view" probe, the same
// route TestServeEndToEnd_RBACDashboard uses for the same purpose.
func dashboardStatusCode(t *testing.T, listenAddr, identity string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// startPolicyReloadServer stands up a real wardline serve subprocess with
// rbac on (an "operator" identity bound to the built-in admin role, which
// carries both dashboard:view and config:edit -- POST
// /dashboard/api/reload/{domain} requires both: the top-level
// rbacadapter.RequirePermission wrap around the whole /dashboard/ tree
// checks dashboard:view before the request ever reaches handleReload's
// own inner config:edit check, see main.go's dashboardRoute wiring) and
// policy seeded from initialPolicyBody. Unlike startWardline, this
// returns policyPath -- the actual on-disk file the running process reads
// policy from -- so a test can overwrite it after the server is up and
// prove a hot-reload picks up the change, which startWardline's own
// internal (test-inaccessible) temp dir doesn't allow. Mirrors the
// manual build/write/start/waitForServer sequence startWardline and
// several other custom setups in this file (e.g.
// TestPolicyPackEndToEnd_InstalledPackIsEnforcedByRealServe) already use.
func startPolicyReloadServer(t *testing.T, initialPolicyBody string) (listenAddr, policyPath string, stderr *safeBuffer) {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath = filepath.Join(dir, "policy.yaml")
	rbacPath := filepath.Join(dir, "rbac.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte(initialPolicyBody), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: operator
    role: admin
`), 0644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	listenAddr = reserveAddr(t)
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
features:
  web_ui: true
  rbac: true
rbac:
  config_file: "%s"
audit:
  output: stdout
`, listenAddr, upstream.URL, policyPath, rbacPath)), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	stderr = &safeBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wardline: %v", err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForServer(t, "http://"+listenAddr)
	return listenAddr, policyPath, stderr
}

// TestServeEndToEnd_PolicyReloadTakesEffectWithoutRestart proves a policy
// hot-reload takes effect on the very next proxied call against the SAME
// running process -- no restart -- by denying alice under the initial
// policy, overwriting the on-disk policy file with a version allowing
// her, hitting POST /dashboard/api/reload/policy as an identity holding
// config:edit, and confirming alice's next call succeeds.
func TestServeEndToEnd_PolicyReloadTakesEffectWithoutRestart(t *testing.T) {
	listenAddr, policyPath, stderr := startPolicyReloadServer(t, `
rules:
  - identity: "bob"
    tool: "read_file"
    effect: allow
default: deny
`)

	deniedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for alice under the initial policy (only bob is allowed), got %d (stderr: %s)", deniedResp.StatusCode, stderr.String())
	}

	if err := os.WriteFile(policyPath, []byte(`
rules:
  - identity: "alice"
    tool: "read_file"
    effect: allow
default: deny
`), 0644); err != nil {
		t.Fatal(err)
	}

	result := postReload(t, listenAddr, "policy", "operator")
	if !result.OK {
		t.Fatalf("expected the policy reload to succeed, got error: %q", result.Error)
	}
	if result.AppliedBy != "operator" {
		t.Errorf("expected AppliedBy %q, got %q", "operator", result.AppliedBy)
	}

	// The VERY NEXT proxied call from alice -- same running process, no
	// restart -- is now allowed.
	allowedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice immediately after the policy reload, got %d (stderr: %s)", allowedResp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_BadPolicyReloadRejectedOldPolicyKeepsServing proves a
// reload attempt with genuinely invalid YAML is rejected by the reload
// endpoint (OK: false, a non-empty Error) and that the previously-loaded
// policy engine is never touched: alice's call, denied before the bad
// reload, is denied identically after it.
func TestServeEndToEnd_BadPolicyReloadRejectedOldPolicyKeepsServing(t *testing.T) {
	listenAddr, policyPath, stderr := startPolicyReloadServer(t, `
rules:
  - identity: "bob"
    tool: "read_file"
    effect: allow
default: deny
`)

	deniedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for alice under the initial policy, got %d (stderr: %s)", deniedResp.StatusCode, stderr.String())
	}

	// Genuinely invalid YAML -- an unterminated flow sequence -- not just
	// a semantically-odd-but-parseable policy.
	if err := os.WriteFile(policyPath, []byte(`
rules:
  - identity: "alice"
    tool: "read_file"
    effect: allow
default: deny
  bad: [unterminated
`), 0644); err != nil {
		t.Fatal(err)
	}

	result := postReload(t, listenAddr, "policy", "operator")
	if result.OK {
		t.Fatal("expected the reload of genuinely invalid policy YAML to be rejected, got OK")
	}
	if result.Error == "" {
		t.Error("expected a non-empty Error on a rejected reload")
	}

	// The old, valid engine never got touched: alice is denied exactly as
	// before.
	stillDeniedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if stillDeniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected alice to still be denied after the rejected reload, got %d (stderr: %s)", stillDeniedResp.StatusCode, stderr.String())
	}
}

// policyInfoResponse mirrors dashboarddomain.PolicyInfo's JSON shape for
// GET/successful-PUT /dashboard/api/policy.
type policyInfoResponse struct {
	Backend string
	Source  string
}

// putPolicy PUTs the dashboard Rule editor's exact wire shape to
// /dashboard/api/policy as identity, returning the raw response so both
// the success case (200, a policyInfoResponse body) and the rejection
// case (400, an {"error": "..."} body) can assert on it directly.
func putPolicy(t *testing.T, listenAddr, identity string, rules []map[string]string, def string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{"rules": rules, "default": def})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, "http://"+listenAddr+"/dashboard/api/policy", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func getPolicyInfo(t *testing.T, listenAddr, identity string) policyInfoResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/policy", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET policy as %s: expected 200, got %d: %s", identity, resp.StatusCode, b)
	}
	var got policyInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("invalid policy response: %v", err)
	}
	return got
}

// TestServeEndToEnd_PolicyRuleEditorWriteTakesEffectWithoutRestart proves
// the dashboard's structured Rule editor -- PUT /dashboard/api/policy,
// not a direct file edit + POST reload like
// TestServeEndToEnd_PolicyReloadTakesEffectWithoutRestart above -- is a
// real, complete write-validate-persist-reload path: the very next
// proxied call reflects the new rules with no restart, AND the very
// next GET /dashboard/api/policy reflects the new Source text (proving
// policyInfoHolder, not a startup-frozen snapshot, is what GET reads).
func TestServeEndToEnd_PolicyRuleEditorWriteTakesEffectWithoutRestart(t *testing.T) {
	listenAddr, _, stderr := startPolicyReloadServer(t, `
rules:
  - identity: "bob"
    tool: "read_file"
    effect: allow
default: deny
`)

	deniedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for alice under the initial policy, got %d (stderr: %s)", deniedResp.StatusCode, stderr.String())
	}

	resp := putPolicy(t, listenAddr, "operator", []map[string]string{
		{"identity": "alice", "tool": "read_file", "effect": "allow"},
	}, "deny")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected the rule editor write to succeed, got %d: %s (stderr: %s)", resp.StatusCode, b, stderr.String())
	}
	var got policyInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if !strings.Contains(got.Source, `identity: alice`) {
		t.Errorf("expected the write response's Source to reflect the new rule, got:\n%s", got.Source)
	}

	// Same running process, no restart: alice is now allowed.
	allowedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice immediately after the rule-editor write, got %d (stderr: %s)", allowedResp.StatusCode, stderr.String())
	}

	// GET /dashboard/api/policy is live too, not a startup-frozen snapshot.
	current := getPolicyInfo(t, listenAddr, "operator")
	if !strings.Contains(current.Source, `identity: alice`) {
		t.Errorf("expected GET /dashboard/api/policy to reflect the write immediately, got:\n%s", current.Source)
	}
}

// TestServeEndToEnd_PolicyRuleEditorInvalidWriteRejectedFileNeverTouched
// proves an invalid structured write (empty tool) is rejected BEFORE
// anything is persisted: the live engine and the on-disk file are both
// exactly as they were, mirroring
// TestServeEndToEnd_BadPolicyReloadRejectedOldPolicyKeepsServing's claim
// for the direct-file-edit path.
func TestServeEndToEnd_PolicyRuleEditorInvalidWriteRejectedFileNeverTouched(t *testing.T) {
	listenAddr, policyPath, stderr := startPolicyReloadServer(t, `
rules:
  - identity: "bob"
    tool: "read_file"
    effect: allow
default: deny
`)
	before, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	resp := putPolicy(t, listenAddr, "operator", []map[string]string{
		{"identity": "alice", "tool": "", "effect": "allow"}, // empty tool -- invalid
	}, "deny")
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for an invalid rule, got %d: %s", resp.StatusCode, b)
	}
	var errBody struct{ Error string }
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("invalid error response: %v", err)
	}
	if errBody.Error == "" {
		t.Error("expected a non-empty error message explaining the rejection")
	}

	after, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("expected the policy file to survive a rejected write byte-for-byte untouched, got:\n%s", after)
	}

	// bob's original rule is still the only thing in effect.
	stillDeniedResp := postToolCall(t, listenAddr, "alice", "read_file")
	if stillDeniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected alice to still be denied after the rejected write, got %d (stderr: %s)", stillDeniedResp.StatusCode, stderr.String())
	}
}

// putBudget PUTs the dashboard Budget editor's exact wire shape to
// /dashboard/api/budget as identity, mirroring putPolicy's exact
// pattern for the Policy editor's own write endpoint.
func putBudget(t *testing.T, listenAddr, identity string, requestsPerWindow, windowSeconds int, tenantOverrides []map[string]any) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"default":          map[string]any{"requests_per_window": requestsPerWindow, "window_seconds": windowSeconds},
		"tenant_overrides": tenantOverrides,
		"tool_overrides":   []map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, "http://"+listenAddr+"/dashboard/api/budget", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// startBudgetReloadServer mirrors startPolicyReloadServer's exact
// pattern (real binary, rbac on, "operator" bound to admin/config:edit)
// but with budget_enforcement on and the given initial budget: section,
// for the Budget editor's own e2e tests.
func startBudgetReloadServer(t *testing.T, initialBudgetBody string) (listenAddr, configPath string, stderr *safeBuffer) {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "policy.yaml")
	rbacPath := filepath.Join(dir, "rbac.yaml")
	configPath = filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte(`default: allow`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: operator
    role: admin
`), 0644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	listenAddr = reserveAddr(t)
	configBody := fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
features:
  web_ui: true
  rbac: true
  budget_enforcement: true
rbac:
  config_file: "%s"
%s
audit:
  output: stdout
`, listenAddr, upstream.URL, policyPath, rbacPath, initialBudgetBody)
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	stderr = &safeBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wardline: %v", err)
	}
	waiter := waitFor(cmd)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-waiter.done
	})
	waitForServer(t, "http://"+listenAddr)
	return listenAddr, configPath, stderr
}

// TestServeEndToEnd_BudgetEditorWriteTakesEffectWithoutRestart proves
// the dashboard's Budget editor -- PUT /dashboard/api/budget -- is a
// real write-validate-persist-reload path, mirroring
// TestServeEndToEnd_PolicyRuleEditorWriteTakesEffectWithoutRestart's
// exact claim for Policy: the very next proxied call reflects the new
// limit with no restart, and every OTHER key in the shared config file
// (listen/upstream/policy_file/rbac/features) survives the surgical
// budget-only edit untouched.
func TestServeEndToEnd_BudgetEditorWriteTakesEffectWithoutRestart(t *testing.T) {
	listenAddr, configPath, stderr := startBudgetReloadServer(t, `
budget:
  requests_per_window: 2
  window_seconds: 300
`)

	// Consume the initial 2-request window entirely.
	for i := 0; i < 2; i++ {
		resp := postToolCall(t, listenAddr, "alice", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for alice's warm-up call %d/2, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}
	throttledResp := postToolCall(t, listenAddr, "alice", "read_file")
	if throttledResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once alice exhausts the initial 2-request window, got %d (stderr: %s)", throttledResp.StatusCode, stderr.String())
	}

	resp := putBudget(t, listenAddr, "operator", 10, 300, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected the budget editor write to succeed, got %d: %s (stderr: %s)", resp.StatusCode, b, stderr.String())
	}

	// Same running process, no restart: the remaining allowance is
	// (new limit - already consumed) = 10-2 = 8, proving live state
	// (not a fresh counter) was preserved across the edit -- same
	// invariant TestServeEndToEnd_BudgetReloadPreservesConsumedUsage
	// establishes for a direct-file-edit reload.
	for i := 0; i < 8; i++ {
		allowedResp := postToolCall(t, listenAddr, "alice", "read_file")
		if allowedResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for alice's post-write call %d/8, got %d (stderr: %s)", i+1, allowedResp.StatusCode, stderr.String())
		}
	}
	nowThrottledResp := postToolCall(t, listenAddr, "alice", "read_file")
	if nowThrottledResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once the raised 10-request window is also exhausted, got %d (stderr: %s)", nowThrottledResp.StatusCode, stderr.String())
	}

	// Every other config key survived the surgical budget-only edit.
	cfg, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "rbac:") || !strings.Contains(string(cfg), "config_file:") {
		t.Errorf("expected the rbac: section to survive the budget-only edit, got:\n%s", cfg)
	}
}

// TestServeEndToEnd_BudgetEditorInvalidWriteRejectedConfigNeverTouched
// proves an invalid budget write (requests_per_window <= 0) is
// rejected BEFORE anything is persisted, mirroring
// TestServeEndToEnd_PolicyRuleEditorInvalidWriteRejectedFileNeverTouched's
// exact claim for Policy.
func TestServeEndToEnd_BudgetEditorInvalidWriteRejectedConfigNeverTouched(t *testing.T) {
	listenAddr, configPath, stderr := startBudgetReloadServer(t, `
budget:
  requests_per_window: 5
  window_seconds: 300
`)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	resp := putBudget(t, listenAddr, "operator", 0, 300, nil) // requests_per_window <= 0 -- invalid
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for an invalid budget, got %d: %s", resp.StatusCode, b)
	}
	var errBody struct{ Error string }
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("invalid error response: %v", err)
	}
	if errBody.Error == "" {
		t.Error("expected a non-empty error message explaining the rejection")
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("expected the config file to survive a rejected write byte-for-byte untouched, got:\n%s", after)
	}

	// The original 5-request limit is still in effect.
	for i := 0; i < 5; i++ {
		resp := postToolCall(t, listenAddr, "alice", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for alice's call %d/5 under the still-original limit, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}
	stillThrottledResp := postToolCall(t, listenAddr, "alice", "read_file")
	if stillThrottledResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 under the still-original 5-request limit, got %d (stderr: %s)", stillThrottledResp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_RBACReloadPreservesLiveSCIMBinding is the test the
// Task 3 doc comment on newRBACReloadFn (cmd/wardline/main.go) warns
// would have caught the "reconstruct instead of reuse the SCIM store" bug
// class: a real SCIM-provisioned RoleBinding must survive a genuinely
// different (but valid) rbac.yaml reload, because newRBACReloadFn
// re-wraps the freshly loaded StaticAuthorizer around the SAME
// scimBindingStore instance rather than constructing a new one.
//
// carol is granted the "viewer" role (dashboard:view) purely via a real
// SCIM Group provisioning call (POST /scim/v2/Groups,
// "wardline:role-viewer") -- rbac.yaml never mentions her. After
// confirming she has dashboard:view, rbac.yaml is overwritten with
// different (but valid) content -- an additional static binding for
// "dave" -- and reloaded. Two things must both be true afterward: carol
// (SCIM-provisioned, untouched by the YAML edit) still has dashboard:view,
// proving her binding survived the reload; and dave (newly added in the
// reloaded YAML) now also has it, proving the new YAML was genuinely
// loaded rather than the old engine having silently kept serving
// unchanged.
func TestServeEndToEnd_RBACReloadPreservesLiveSCIMBinding(t *testing.T) {
	dir := t.TempDir()
	rbacPath := filepath.Join(dir, "rbac.yaml")
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: operator
    role: admin
`), 0644); err != nil {
		t.Fatal(err)
	}

	const scimToken = "scim-bearer-token-for-rbac-reload-e2e"
	t.Setenv("WARDLINE_E2E_RBAC_RELOAD_SCIM_TOKEN", scimToken)

	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `default: allow`, fmt.Sprintf(`features:
  web_ui: true
  rbac: true
  scim: true
rbac:
  config_file: "%s"
scim:
  bearer_token_env: "WARDLINE_E2E_RBAC_RELOAD_SCIM_TOKEN"`, rbacPath))

	// Provision carol's viewer access entirely via SCIM -- rbac.yaml never
	// mentions her.
	carolID := scimCreateUser(t, listenAddr, scimToken, "carol")
	scimCreateGroup(t, listenAddr, scimToken, "wardline:role-viewer", []string{carolID})

	if code := dashboardStatusCode(t, listenAddr, "carol"); code != http.StatusOK {
		t.Fatalf("expected 200 for carol's SCIM-provisioned viewer binding, got %d (stderr: %s)", code, stderr.String())
	}

	// A genuinely different, but valid, rbac.yaml -- an added static
	// binding for dave, "operator" retained so the reload call below still
	// has config:edit.
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: operator
    role: admin
  - subject: dave
    role: viewer
`), 0644); err != nil {
		t.Fatal(err)
	}

	result := postReload(t, listenAddr, "rbac", "operator")
	if !result.OK {
		t.Fatalf("expected the rbac reload to succeed, got error: %q", result.Error)
	}

	// carol's live SCIM binding survived the reload.
	if code := dashboardStatusCode(t, listenAddr, "carol"); code != http.StatusOK {
		t.Fatalf("expected carol's SCIM-provisioned viewer binding to survive the rbac reload, got %d (stderr: %s)", code, stderr.String())
	}
	// dave's newly-added static binding proves the new YAML was genuinely
	// loaded, not that the old engine was left untouched.
	if code := dashboardStatusCode(t, listenAddr, "dave"); code != http.StatusOK {
		t.Fatalf("expected dave's newly-reloaded static viewer binding to be honored, got %d (stderr: %s)", code, stderr.String())
	}
}

// TestServeEndToEnd_BudgetReloadPreservesConsumedUsage proves a budget
// reload that raises the limit updates the SAME running limiter's
// threshold in place (newBudgetReloadFn, cmd/wardline/main.go) rather
// than swapping in a fresh limiter instance: alice consumes 4 of an
// initial 5-request window, the limit is then raised to 20 via a config
// reload, and her remaining allowance is exactly 20-4=16 more successful
// calls followed by a 429 -- not a fresh 20, which is what a silently
// reset counter would allow.
func TestServeEndToEnd_BudgetReloadPreservesConsumedUsage(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")
	policyPath := filepath.Join(dir, "policy.yaml")
	rbacPath := filepath.Join(dir, "rbac.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")

	if err := os.WriteFile(policyPath, []byte(`default: allow`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rbacPath, []byte(`
bindings:
  - subject: operator
    role: admin
`), 0644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	listenAddr := reserveAddr(t)
	// window_seconds is deliberately long (300s) and left UNCHANGED by the
	// reload below -- only requests_per_window rises -- so the window
	// never rolls over mid-test and the only variable in play is the
	// threshold change itself.
	configBody := fmt.Sprintf(`
listen: "%s"
upstream: "%s"
policy_file: "%s"
features:
  web_ui: true
  rbac: true
  budget_enforcement: true
rbac:
  config_file: "%s"
budget:
  requests_per_window: 5
  window_seconds: 300
audit:
  output: stdout
`, listenAddr, upstream.URL, policyPath, rbacPath)
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
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
	waitForServer(t, "http://"+listenAddr)

	// Consume 4 of the initial 5-request window.
	for i := 0; i < 4; i++ {
		resp := postToolCall(t, listenAddr, "alice", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for alice's warm-up call %d/4, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}

	// Raise the limit via a config reload -- same window_seconds, higher
	// requests_per_window.
	raisedConfigBody := strings.Replace(configBody, "requests_per_window: 5", "requests_per_window: 20", 1)
	if err := os.WriteFile(configPath, []byte(raisedConfigBody), 0644); err != nil {
		t.Fatal(err)
	}

	result := postReload(t, listenAddr, "budget", "operator")
	if !result.OK {
		t.Fatalf("expected the budget reload to succeed, got error: %q", result.Error)
	}

	// Remaining allowance is (new limit - already consumed) = 20-4 = 16,
	// not a fresh 20: exactly 16 more calls succeed...
	for i := 0; i < 16; i++ {
		resp := postToolCall(t, listenAddr, "alice", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for alice's post-reload call %d/16 (remaining allowance 20-4=16), got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}
	// ...and the next one (the 21st overall, exceeding the raised limit of
	// 20) is throttled -- proving the counter genuinely survived the
	// reload rather than being silently reset to a fresh 20.
	throttledResp := postToolCall(t, listenAddr, "alice", "read_file")
	if throttledResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for alice's 21st call (exceeding the raised limit of 20, proving the pre-reload usage of 4 survived), got %d (stderr: %s)", throttledResp.StatusCode, stderr.String())
	}
}
