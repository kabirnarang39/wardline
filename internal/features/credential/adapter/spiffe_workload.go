package adapter

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// This file makes Wardline itself a SPIFFE workload -- distinct from
// mtls.go's MTLSBootstrapper, which trusts an ALREADY-VERIFIED SPIFFE ID
// forwarded by a terminating mTLS proxy/mesh on an inbound request
// (Wardline never terminates TLS or parses X.509 itself for INBOUND
// traffic -- see mtls.go's own doc comment, unchanged by this file).
// SPIFFEWorkloadIdentity is the OUTBOUND half: Wardline fetching its own
// X.509-SVID from a local SPIRE agent's Workload API, for connections
// Wardline itself initiates (an upstream, a federation peer) that want
// real mutual TLS -- Wardline presenting its own workload identity, not
// just verifying the far end's.

// spiffeWorkloadAPITimeout bounds the initial connection to the local
// Workload API -- a misconfigured or absent SPIRE agent must fail fast
// at startup, not hang wardline serve indefinitely. Ongoing SVID
// rotation after that (workloadapi.X509Source watches for updates in
// its own background goroutine) has no such bound; it's expected to sit
// idle between rotations.
const spiffeWorkloadAPITimeout = 10 * time.Second

// SPIFFEWorkloadIdentity holds this Wardline instance's own SPIFFE
// identity: an X.509-SVID fetched from, and continuously auto-rotated
// by, a local SPIRE agent's Workload API (the standard SPIFFE
// Workload API, typically a Unix domain socket -- see
// SPIFFE_ENDPOINT_SOCKET / credential.spiffe_workload.socket_path).
// Wraps workloadapi.X509Source, the official go-spiffe SDK's own
// auto-rotating source type -- this adapter doesn't re-implement
// rotation, certificate parsing, or trust bundle management, all of
// which the SDK already does correctly.
type SPIFFEWorkloadIdentity struct {
	source *workloadapi.X509Source
}

// NewSPIFFEWorkloadIdentity connects to the Workload API at socketPath
// (empty uses the SDK's own SPIFFE_ENDPOINT_SOCKET environment-variable
// default) and fetches this workload's initial X.509-SVID, failing fast
// if no SPIRE agent is reachable there -- same fail-fast-at-construction
// posture as every other network-backed adapter in this codebase.
func NewSPIFFEWorkloadIdentity(ctx context.Context, socketPath string) (*SPIFFEWorkloadIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, spiffeWorkloadAPITimeout)
	defer cancel()
	var opts []workloadapi.X509SourceOption
	if socketPath != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to spiffe workload api: %w", err)
	}
	return &SPIFFEWorkloadIdentity{source: source}, nil
}

// ID returns this workload's current SPIFFE ID (e.g.
// "spiffe://example.org/wardline") -- the identity Wardline presents on
// every outbound mTLS connection using ClientTLSConfig.
func (s *SPIFFEWorkloadIdentity) ID() (spiffeid.ID, error) {
	svid, err := s.source.GetX509SVID()
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("get current svid: %w", err)
	}
	return svid.ID, nil
}

// ClientTLSConfig returns a *tls.Config that presents this workload's
// own (continuously rotating) SVID as the client certificate on an
// outbound TLS connection, and verifies the SERVER's certificate is
// itself a valid SPIFFE SVID authorized by authorizer -- real mutual
// TLS between two SPIFFE workloads, e.g.
// tlsconfig.AuthorizeID(peerID) to pin one exact expected peer, or
// tlsconfig.AuthorizeMemberOf(trustDomain) to accept any workload in a
// trust domain. Safe to call repeatedly; the returned config always
// reads the source's live (rotated) SVID/bundle on each handshake, it
// does not freeze the SVID present at call time.
func (s *SPIFFEWorkloadIdentity) ClientTLSConfig(authorizer tlsconfig.Authorizer) *tls.Config {
	return tlsconfig.MTLSClientConfig(s.source, s.source, authorizer)
}

// Close releases the Workload API connection and stops SVID rotation.
func (s *SPIFFEWorkloadIdentity) Close() error {
	return s.source.Close()
}
