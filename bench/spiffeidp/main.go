// Command spiffeidp is a minimal, self-contained SPIFFE Workload API
// server for benchmarking spiffe_workload_identity + grpc_upstream_tls
// under load without a real SPIRE deployment (docker/spire-server/
// spire-agent, join tokens, workload attestation) -- mirrors how
// bench/httpupstream/bench/oidcidp stand in for real infrastructure
// elsewhere in this suite. Implements only the one RPC
// credentialadapter.SPIFFEWorkloadIdentity's workloadapi.X509Source
// actually calls (FetchX509SVID), using the go-spiffe SDK's own
// generated proto types -- not a reimplementation of the wire protocol,
// just the server side of it.
//
// Generates a self-signed CA, issues an X.509-SVID for wardline's own
// outbound identity (served over a Unix domain socket, the real
// Workload API transport), and a SECOND X.509-SVID for the upstream gRPC
// server to present (written to files) -- so grpcload's "upstream -tls"
// mode and wardline both terminate real mutual TLS against the same
// trust bundle, proving the whole chain, not just one half of it.
//
// Usage:
//
//	spiffeidp <uds-socket-path> <wardline-spiffe-id> <upstream-spiffe-id> <upstream-cert-out> <upstream-key-out> <ca-cert-out>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

// svidTTL is generous relative to any bench run's duration -- this
// process's whole point is a static identity for the run, not testing
// SPIRE's own rotation behavior (a real SPIRE agent's rotation is
// exercised by the gated real-SPIRE-agent tests in
// internal/features/credential/adapter/spiffe_workload_test.go, not
// here).
const svidTTL = 1 * time.Hour

func main() {
	if len(os.Args) != 7 {
		fmt.Fprintln(os.Stderr, "usage: spiffeidp <uds-socket-path> <wardline-spiffe-id> <upstream-spiffe-id> <upstream-cert-out> <upstream-key-out> <ca-cert-out>")
		os.Exit(2)
	}
	socketPath, wardlineID, upstreamID, upstreamCertOut, upstreamKeyOut, caCertOut := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]

	caCert, caKey, err := generateCA()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate ca:", err)
		os.Exit(1)
	}

	wardlineCert, wardlineKey, err := issueLeaf(caCert, caKey, wardlineID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue wardline svid:", err)
		os.Exit(1)
	}
	upstreamCert, upstreamKey, err := issueLeaf(caCert, caKey, upstreamID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue upstream svid:", err)
		os.Exit(1)
	}

	if err := writeCertKeyPEM(upstreamCertOut, upstreamKeyOut, upstreamCert, upstreamKey, caCert); err != nil {
		fmt.Fprintln(os.Stderr, "write upstream svid files:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(caCertOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write ca cert file:", err)
		os.Exit(1)
	}

	wardlineKeyDER, err := x509.MarshalPKCS8PrivateKey(wardlineKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal wardline key:", err)
		os.Exit(1)
	}

	resp := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    wardlineID,
				X509Svid:    wardlineCert.Raw,
				X509SvidKey: wardlineKeyDER,
				Bundle:      caCert.Raw,
			},
		},
	}

	_ = os.Remove(socketPath) // stale socket from a prior run
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen on uds:", err)
		os.Exit(1)
	}

	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, &fakeWorkloadAPI{resp: resp})
	fmt.Printf("spiffeidp serving Workload API on %s (wardline_id=%s upstream_id=%s)\n", socketPath, wardlineID, upstreamID)
	if err := srv.Serve(lis); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

// fakeWorkloadAPI implements only FetchX509SVID -- the sole RPC
// workloadapi.X509Source calls. Sends the one static response, then
// blocks until the client disconnects: the real Workload API is a
// streaming RPC that pushes new messages only on rotation, and this
// process issues exactly one SVID for the run's whole life, so holding
// the stream open with no further message is the correct behavior, not
// a shortcut.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	resp *workload.X509SVIDResponse
}

func (f *fakeWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := stream.Send(f.resp); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spiffeidp bench CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(svidTTL),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// issueLeaf issues an X.509-SVID for spiffeID: a leaf certificate whose
// URI SAN is the SPIFFE ID itself, signed by the CA -- exactly the shape
// tlsconfig.AuthorizeID/AuthorizeAny (go-spiffe's peer verification)
// expects.
func issueLeaf(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, nil, fmt.Errorf("parse spiffe id %q: %w", spiffeID, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: spiffeID},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(svidTTL),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:           []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func writeCertKeyPEM(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey, ca *x509.Certificate) error {
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer func() { _ = certOut.Close() }()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}
	// Append the CA cert so the file is a full chain -- the upstream TLS
	// listener's tls.Config.Certificates entry needs the chain, and
	// callers that load this file to build a CertPool (the mTLS client
	// verification side) get the CA in the same place.
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = keyOut.Close() }()
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
