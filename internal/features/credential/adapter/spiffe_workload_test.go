package adapter_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
)

// spiffeSocketOrSkip skips the test unless SPIFFE_ENDPOINT_SOCKET names
// a reachable Workload API (a real SPIRE agent, or the spiffe-helper /
// spire-server's own local-socket test fixture) -- same
// real-external-dependency gating convention as testDSN's
// WARDLINE_TEST_POSTGRES_DSN elsewhere in this codebase: these prove
// the real wire protocol against a real SPIRE agent, not a fake, and
// simply don't run without one configured.
//
// Start a local SPIRE agent for manual testing with:
//
//	spire-agent run -config agent.conf
//
// and set SPIFFE_ENDPOINT_SOCKET to its unix:// socket path (see
// https://github.com/spiffe/spire for a full quickstart).
func spiffeSocketOrSkip(t *testing.T) string {
	t.Helper()
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		t.Skip("SPIFFE_ENDPOINT_SOCKET not set, skipping real-SPIRE-agent integration test")
	}
	return socket
}

func TestNewSPIFFEWorkloadIdentity_FetchesRealSVID(t *testing.T) {
	socket := spiffeSocketOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w, err := adapter.NewSPIFFEWorkloadIdentity(ctx, socket)
	if err != nil {
		t.Fatalf("NewSPIFFEWorkloadIdentity: %v", err)
	}
	defer func() { _ = w.Close() }()

	id, err := w.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if id.String() == "" {
		t.Error("expected a non-empty SPIFFE ID from a real Workload API")
	}
}

func TestSPIFFEWorkloadIdentity_ClientTLSConfig_PresentsClientCertificates(t *testing.T) {
	socket := spiffeSocketOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w, err := adapter.NewSPIFFEWorkloadIdentity(ctx, socket)
	if err != nil {
		t.Fatalf("NewSPIFFEWorkloadIdentity: %v", err)
	}
	defer func() { _ = w.Close() }()

	cfg := w.ClientTLSConfig(tlsconfig.AuthorizeAny())
	if cfg.GetClientCertificate == nil {
		t.Fatal("expected a *tls.Config with GetClientCertificate set (presents this workload's own SVID)")
	}
	cert, err := cfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected a non-empty client certificate chain from a real Workload API")
	}
}

func TestNewSPIFFEWorkloadIdentity_UnreachableSocketFailsFast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err := adapter.NewSPIFFEWorkloadIdentity(ctx, "unix:///tmp/wardline-test-nonexistent-spire-agent.sock")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error connecting to a socket with no SPIRE agent listening")
	}
	if elapsed > 5*time.Second {
		t.Errorf("expected NewSPIFFEWorkloadIdentity to fail fast (bounded by its own internal timeout), took %v", elapsed)
	}
}
