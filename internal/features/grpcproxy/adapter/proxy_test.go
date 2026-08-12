package adapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	proxydomain "github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

const testMethod = "/test.Echo/Call"

// --- fakes -------------------------------------------------------------

type fakeDecider struct {
	allow  bool
	reason string
}

func (f fakeDecider) Decide(proxydomain.ToolCall) proxydomain.Verdict {
	return proxydomain.Verdict{Allow: f.allow, Reason: f.reason}
}

type fakeBudget struct {
	allowed bool
	reason  string
}

func (f fakeBudget) Check(string, string, string, time.Time) budgetdomain.Verdict {
	return budgetdomain.Verdict{Allowed: f.allowed, Reason: f.reason}
}

type fakeBlock struct {
	allowed bool
	reason  string
}

func (f fakeBlock) Check(string, string, time.Time) anomalydomain.BlockVerdict {
	return anomalydomain.BlockVerdict{Allowed: f.allowed, Reason: f.reason}
}

type recorded struct {
	identity, tenant, tool, decision, reason string
}

type fakeRecorder struct {
	mu      sync.Mutex
	entries []recorded
}

func (r *fakeRecorder) Record(identity, tenant, tool, decision, reason, _ string, _ time.Duration, _ time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, recorded{identity, tenant, tool, decision, reason})
}

func (r *fakeRecorder) only(t *testing.T) recorded {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.entries, 1, "expected exactly one audit entry")
	return r.entries[0]
}

// echoHandler is a transparent upstream: it reflects each raw frame back.
func echoHandler(_ any, ss grpc.ServerStream) error {
	f := &rawFrame{}
	for {
		if err := ss.RecvMsg(f); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := ss.SendMsg(f); err != nil {
			return err
		}
	}
}

// --- harness -----------------------------------------------------------

// harness wires: echo upstream <- proxy <- test client, all over bufconn.
type harness struct {
	clientConn *grpc.ClientConn
	recorder   *fakeRecorder
	stop       func()
}

func newHarness(t *testing.T, decider PolicyDecider, budget BudgetChecker, block AutoBlockChecker) *harness {
	t.Helper()

	// Upstream echo server.
	upLis := bufconn.Listen(1 << 20)
	upSrv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(echoHandler))
	go func() { _ = upSrv.Serve(upLis) }()

	upConn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return upLis.DialContext(context.Background()) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	require.NoError(t, err)

	rec := &fakeRecorder{}
	proxy := NewProxy(decider, budget, block, rec, MetadataIdentity{}, upConn, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Proxy server.
	pxLis := bufconn.Listen(1 << 20)
	pxSrv := grpc.NewServer(proxy.ServerOptions()...)
	go func() { _ = pxSrv.Serve(pxLis) }()

	cli, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return pxLis.DialContext(context.Background()) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	require.NoError(t, err)

	return &harness{
		clientConn: cli,
		recorder:   rec,
		stop: func() {
			_ = cli.Close()
			pxSrv.Stop()
			_ = upConn.Close()
			upSrv.Stop()
		},
	}
}

// call invokes the unary echo method through the proxy with the given
// identity metadata, returning the echoed payload and the RPC error.
func (h *harness) call(identity, tenant string, payload []byte) ([]byte, error) {
	ctx := metadata.AppendToOutgoingContext(context.Background(), metaIdentity, identity, metaTenant, tenant)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req := &rawFrame{payload: payload}
	resp := &rawFrame{}
	err := h.clientConn.Invoke(ctx, testMethod, req, resp)
	return resp.payload, err
}

// --- tests -------------------------------------------------------------

func TestProxy_AllowForwardsAndRecords(t *testing.T) {
	h := newHarness(t, fakeDecider{allow: true}, fakeBudget{allowed: true}, nil)
	defer h.stop()

	got, err := h.call("acme-alice", "acme", []byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, []byte("ping"), got, "upstream echo should relay verbatim")

	e := h.recorder.only(t)
	assert.Equal(t, recorded{"acme-alice", "acme", testMethod, "allow", ""}, e)
}

func TestProxy_PolicyDenyBlocksBeforeUpstream(t *testing.T) {
	h := newHarness(t, fakeDecider{allow: false, reason: "no matching rule"}, fakeBudget{allowed: true}, nil)
	defer h.stop()

	_, err := h.call("globex-dave", "globex", []byte("x"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	// Generic message to caller; detailed reason only in the audit log.
	assert.NotContains(t, status.Convert(err).Message(), "no matching rule")

	e := h.recorder.only(t)
	assert.Equal(t, "deny", e.decision)
	assert.Equal(t, "no matching rule", e.reason)
}

func TestProxy_BudgetThrottle(t *testing.T) {
	h := newHarness(t, fakeDecider{allow: true}, fakeBudget{allowed: false, reason: "budget: 5/60s exceeded"}, nil)
	defer h.stop()

	_, err := h.call("globex-erin", "globex", []byte("x"))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	e := h.recorder.only(t)
	assert.Equal(t, "throttled", e.decision)
}

func TestProxy_AutoBlock(t *testing.T) {
	h := newHarness(t, fakeDecider{allow: true}, fakeBudget{allowed: true}, fakeBlock{allowed: false, reason: "auto-block, rate-spike"})
	defer h.stop()

	_, err := h.call("globex-dave", "globex", []byte("x"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	e := h.recorder.only(t)
	assert.Equal(t, "blocked", e.decision)
}

func TestProxy_UnauthenticatedIsNotAudited(t *testing.T) {
	// Bearer resolver with no token in metadata -> Unauthenticated, and (like
	// the HTTP path) no audit entry for a caller rejected before policy.
	rec := &fakeRecorder{}
	upLis := bufconn.Listen(1 << 20)
	upSrv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(echoHandler))
	go func() { _ = upSrv.Serve(upLis) }()
	defer upSrv.Stop()
	upConn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return upLis.DialContext(context.Background()) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	require.NoError(t, err)
	defer func() { _ = upConn.Close() }()

	proxy := NewProxy(fakeDecider{allow: true}, fakeBudget{allowed: true}, nil, rec,
		NewBearerIdentity(fakeTokenAuth{}), upConn, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pxLis := bufconn.Listen(1 << 20)
	pxSrv := grpc.NewServer(proxy.ServerOptions()...)
	go func() { _ = pxSrv.Serve(pxLis) }()
	defer pxSrv.Stop()
	cli, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return pxLis.DialContext(context.Background()) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	require.NoError(t, err)
	defer func() { _ = cli.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = cli.Invoke(ctx, testMethod, &rawFrame{payload: []byte("x")}, &rawFrame{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Empty(t, rec.entries, "auth failure must not be audited")
}

type fakeTokenAuth struct{}

func (fakeTokenAuth) Authenticate(string) (string, string, error) {
	return "", "", errMissingBearerToken
}

// TestDialUpstream_TLSFlagEngagesTransportSecurity proves the useTLS flag
// actually switches transport security: against one plaintext gRPC server,
// the plaintext dial completes an RPC while the TLS dial fails the
// handshake (a TLS client cannot talk to a plaintext server).
func TestDialUpstream_TLSFlagEngagesTransportSecurity(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(echoHandler))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	addr := lis.Addr().String()

	invoke := func(conn *grpc.ClientConn) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp := &rawFrame{}
		err := conn.Invoke(ctx, testMethod, &rawFrame{payload: []byte("ping")}, resp)
		return resp.payload, err
	}

	plain, err := DialUpstream(addr, false, nil)
	require.NoError(t, err)
	defer func() { _ = plain.Close() }()
	got, err := invoke(plain)
	require.NoError(t, err, "plaintext dial to a plaintext server should succeed")
	assert.Equal(t, []byte("ping"), got)

	secure, err := DialUpstream(addr, true, nil)
	require.NoError(t, err) // NewClient dials lazily; the failure surfaces on the call
	defer func() { _ = secure.Close() }()
	_, err = invoke(secure)
	require.Error(t, err, "TLS dial to a plaintext server must fail the handshake")
}

// TestDialUpstream_ClientTLSConfigOverridesDefault proves the
// clientTLSConfig parameter actually replaces the default
// system-root-verified config, not just gets ignored: the default
// config rejects a self-signed server certificate, but a custom config
// that explicitly trusts it succeeds -- the exact shape
// SPIFFEWorkloadIdentity.ClientTLSConfig relies on (its own trust
// decision, not the system root pool).
func TestDialUpstream_ClientTLSConfigOverridesDefault(t *testing.T) {
	cert := generateSelfSignedCert(t)

	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(echoHandler))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	addr := lis.Addr().String()

	invoke := func(conn *grpc.ClientConn) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return conn.Invoke(ctx, testMethod, &rawFrame{payload: []byte("ping")}, &rawFrame{})
	}

	// Default config: the self-signed cert isn't in the system root
	// pool, so this must fail.
	defaultConn, err := DialUpstream(addr, true, nil)
	require.NoError(t, err)
	defer func() { _ = defaultConn.Close() }()
	require.Error(t, invoke(defaultConn), "expected the default system-root-verified config to reject a self-signed certificate")

	// Custom config: explicitly trusts this exact certificate --
	// clientTLSConfig must be the config actually used, not silently
	// discarded in favor of the default.
	pool := x509.NewCertPool()
	pool.AddCert(mustParseCert(t, cert))
	customConn, err := DialUpstream(addr, true, &tls.Config{RootCAs: pool})
	require.NoError(t, err)
	defer func() { _ = customConn.Close() }()
	require.NoError(t, invoke(customConn), "expected the custom clientTLSConfig (which trusts this cert) to be honored, not overridden by the default")
}

func mustParseCert(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	return parsed
}

// generateSelfSignedCert builds a fresh, valid-for-this-test-only
// self-signed TLS certificate for 127.0.0.1 -- generated at test time
// rather than a checked-in static PEM, so there's no future expiry to
// silently start failing this test.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
