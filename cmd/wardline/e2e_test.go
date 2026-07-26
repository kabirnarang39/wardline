package main_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestServeEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"result":"ok"}`)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	configPath := filepath.Join(dir, "wardline.yaml")
	listenAddr := "127.0.0.1:18080"

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
  output: stdout
`, listenAddr, upstream.URL, policyPath)), 0644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "wardline")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(binPath, "serve", "--config", configPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wardline: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	waitForServer(t, "http://"+listenAddr)

	allowResp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for allowed call, got %d (stderr: %s)", allowResp.StatusCode, stderr.String())
	}

	denyResp := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for denied call, got %d (stderr: %s)", denyResp.StatusCode, stderr.String())
	}
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
