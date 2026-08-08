// Package adapter is the gRPC transport for Wardline: a transparent
// reverse proxy that relays any gRPC method to an upstream server, running
// the exact same identity -> auto-block -> policy -> budget -> audit
// pipeline the HTTP transport does. It never decodes a message body (see
// codec.go), so it needs no relayed service's protobuf schema; the gRPC
// full method name (e.g. "/pkg.Service/Method") is the audited/policy-keyed
// "tool", under the policy method namespace "grpc".
package adapter

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	proxydomain "github.com/kabirnarang39/wardline/internal/features/proxy/domain"
)

// grpcMethod is the policy method namespace for gRPC calls, the transport's
// analogue of "tools/call" for MCP. A policy rule opts into gRPC by setting
// `method: grpc` and `tool: /pkg.Service/Method`; because a blank-method
// rule means "tools/call", no existing MCP rule accidentally matches a gRPC
// call, and an un-allow-listed gRPC method falls through to the default
// effect (deny) exactly like any other unmatched call.
const grpcMethod = "grpc"

// PolicyDecider evaluates a call against policy. *proxy/usecase.Decider
// satisfies it -- reused verbatim so both transports share one policy
// engine (and one hot-reload holder).
type PolicyDecider interface {
	Decide(call proxydomain.ToolCall) proxydomain.Verdict
}

// BudgetChecker is budget/usecase.Checker's shape (identical to
// proxy/adapter.BudgetChecker).
type BudgetChecker interface {
	Check(identity, tenant, tool string, now time.Time) budgetdomain.Verdict
}

// AutoBlockChecker is anomaly/usecase.BlockChecker's shape (identical to
// proxy/adapter.AutoBlockChecker). Nil-able: nil means the anomaly feature
// is off, and the auto-block gate is skipped.
type AutoBlockChecker interface {
	Check(identity, tenantName string, now time.Time) anomalydomain.BlockVerdict
}

// Recorder writes exactly one audit entry per RPC. audit/usecase.Recorder
// satisfies it -- the same sink the HTTP transport records to, so gRPC and
// HTTP traffic share one audit trail and one dashboard.
type Recorder interface {
	Record(identity, tenant, tool, decision, reason, traceID string, latency time.Duration, at time.Time)
}

// Proxy holds the shared enforcement dependencies and the upstream gRPC
// connection. One instance backs the whole gRPC server via Handler.
type Proxy struct {
	decider   PolicyDecider
	budget    BudgetChecker
	autoBlock AutoBlockChecker
	recorder  Recorder
	identity  IdentityResolver
	upstream  *grpc.ClientConn
	logger    *slog.Logger
	now       func() time.Time
}

// NewProxy builds a Proxy. autoBlock may be nil (anomaly feature off).
func NewProxy(decider PolicyDecider, budget BudgetChecker, autoBlock AutoBlockChecker, recorder Recorder, identity IdentityResolver, upstream *grpc.ClientConn, logger *slog.Logger) *Proxy {
	return &Proxy{
		decider:   decider,
		budget:    budget,
		autoBlock: autoBlock,
		recorder:  recorder,
		identity:  identity,
		upstream:  upstream,
		logger:    logger,
		now:       time.Now,
	}
}

// DialUpstream connects to the upstream gRPC target with the raw passthrough
// codec forced as the default call codec, so every relayed call carries
// message bytes verbatim and never needs the upstream's protobuf schema.
// grpc.NewClient dials lazily; the caller owns Close.
//
// useTLS selects transport security: false keeps the historical plaintext
// dial (correct when TLS to the upstream is terminated by a mesh/sidecar);
// true uses TLS verified against the host's system root pool, with the
// server name taken from target -- for a private CA, add it to the
// container's trust store (a mounted CA bundle) rather than passing a
// custom pool here.
func DialUpstream(target string, useTLS bool) (*grpc.ClientConn, error) {
	creds := grpc.WithTransportCredentials(insecure.NewCredentials())
	if useTLS {
		creds = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	return grpc.NewClient(target,
		creds,
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
}

// ServerOptions returns the grpc.ServerOptions that make a grpc.NewServer
// route every RPC -- for any service, known or not -- through Handler with
// the raw passthrough codec. The caller owns server construction and
// lifecycle; this keeps all the "how the transparent proxy is wired" detail
// in one place.
func (p *Proxy) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(p.Handler),
	}
}

// clientStreamDesc describes the upstream stream as fully bidirectional.
// Unary and one-way-streaming methods are strict subsets of a bidi stream
// at the wire level, so one desc relays every RPC kind; the byte pumps
// below simply see fewer messages / an earlier EOF.
var clientStreamDesc = &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}

// Handler is the grpc.StreamHandler installed as the unknown-service
// handler. It enforces the pipeline once at RPC start (mirroring the HTTP
// ServeHTTP's single decision per request), then relays the stream to
// upstream, recording exactly one audit entry.
func (p *Proxy) Handler(_ any, serverStream grpc.ServerStream) error {
	start := p.now()
	fullMethod, ok := grpc.MethodFromServerStream(serverStream)
	if !ok {
		return status.Error(codes.Internal, "cannot determine method")
	}
	ctx := serverStream.Context()
	md, _ := metadata.FromIncomingContext(ctx)

	// Authentication first: a rejected caller never reaches policy, budget,
	// or the audit log -- identical ordering to the HTTP transport. The
	// default MetadataIdentity never errors, so this is a no-op unless
	// credential issuance wires a bearer resolver.
	identity, tenant, err := p.identity.Resolve(md)
	if err != nil {
		p.logger.Warn("grpc identity resolution failed", "method", fullMethod)
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}

	// Auto-block gate runs before policy, exactly as in ServeHTTP.
	if p.autoBlock != nil {
		if v := p.autoBlock.Check(identity, tenant, start); !v.Allowed {
			p.record(identity, tenant, fullMethod, "blocked", v.Reason, start)
			return status.Error(codes.PermissionDenied, "blocked due to anomalous behavior")
		}
	}

	verdict := p.decider.Decide(proxydomain.ToolCall{
		Identity:   identity,
		Tenant:     tenant,
		Tool:       fullMethod,
		Method:     grpcMethod,
		Timestamp:  start,
		RemoteAddr: remoteAddr(ctx),
	})
	if !verdict.Allow {
		// verdict.Reason may carry policy-engine diagnostics -- audit it for
		// the operator, never echo it to the untrusted caller. Same rule as
		// the HTTP deny path.
		p.record(identity, tenant, fullMethod, "deny", verdict.Reason, start)
		return status.Error(codes.PermissionDenied, "denied by policy")
	}

	// Budget is tool-call-scoped in both transports; the gRPC method is the
	// budget key, just as the MCP tool name is on the HTTP path.
	if bv := p.budget.Check(identity, tenant, fullMethod, start); !bv.Allowed {
		p.record(identity, tenant, fullMethod, "throttled", bv.Reason, start)
		return status.Error(codes.ResourceExhausted, "throttled by budget")
	}

	return p.forward(ctx, serverStream, fullMethod, md, identity, tenant, start)
}

// forward opens the upstream stream and relays messages both ways until one
// side finishes, recording one audit entry for the outcome. It's the gRPC
// analogue of the HTTP forward(): strip the caller's credentials before they
// reach the untrusted upstream, then proxy.
func (p *Proxy) forward(ctx context.Context, serverStream grpc.ServerStream, fullMethod string, md metadata.MD, identity, tenant string, start time.Time) error {
	// Strip the caller's Wardline credentials before forwarding upstream --
	// the untrusted upstream must never learn the identity headers or bearer
	// token it needs to impersonate the caller. Same reasoning as the HTTP
	// path deleting Authorization / the trusted identity header.
	outMD := md.Copy()
	outMD.Delete(metaAuth)
	outMD.Delete(metaIdentity)
	outMD.Delete(metaTenant)
	outCtx, cancel := context.WithCancel(metadata.NewOutgoingContext(ctx, outMD))
	defer cancel()

	clientStream, err := p.upstream.NewStream(outCtx, clientStreamDesc, fullMethod)
	if err != nil {
		p.record(identity, tenant, fullMethod, "error", err.Error(), start)
		return status.Error(codes.Unavailable, "upstream unreachable")
	}

	s2c := forwardServerToClient(serverStream, clientStream)
	c2s := forwardClientToServer(clientStream, serverStream)

	// Wait for both directions. The server->client pump finishing with EOF
	// means the caller sent everything, so half-close the upstream. The
	// client->server pump finishing carries the RPC's final status: EOF is a
	// clean allow, any other error is the upstream's status verbatim.
	for i := 0; i < 2; i++ {
		select {
		case err := <-s2c:
			if err == io.EOF {
				// Caller done sending; tell upstream. Its response may still
				// be in flight -- keep waiting on c2s.
				_ = clientStream.CloseSend()
				continue
			}
			// A real error reading from / sending to the caller: cancel the
			// upstream and report.
			cancel()
			p.record(identity, tenant, fullMethod, "error", err.Error(), start)
			return status.Errorf(codes.Internal, "stream relay failed: %v", err)
		case err := <-c2s:
			// Upstream response fully relayed. Propagate its trailer to the
			// caller regardless of outcome.
			serverStream.SetTrailer(clientStream.Trailer())
			if err == io.EOF {
				p.record(identity, tenant, fullMethod, "allow", "", start)
				return nil
			}
			// Non-EOF: the upstream ended the RPC with a status. Record it as
			// an upstream error and return the status verbatim so the caller
			// sees the real code/message.
			p.record(identity, tenant, fullMethod, "error", err.Error(), start)
			return err
		}
	}
	return status.Error(codes.Internal, "stream relay ended unexpectedly")
}

// forwardServerToClient pumps request messages from the caller to upstream,
// forwarding raw frames until the caller half-closes (io.EOF) or a relay
// error occurs. The result is delivered on the returned channel exactly once.
func forwardServerToClient(src grpc.ServerStream, dst grpc.ClientStream) chan error {
	ret := make(chan error, 1)
	go func() {
		f := &rawFrame{}
		for {
			if err := src.RecvMsg(f); err != nil {
				ret <- err // io.EOF on clean caller half-close
				return
			}
			if err := dst.SendMsg(f); err != nil {
				ret <- err
				return
			}
		}
	}()
	return ret
}

// forwardClientToServer pumps response messages from upstream back to the
// caller. On the first response it forwards upstream's header metadata, then
// relays frames until upstream ends the RPC (io.EOF on success, or a status
// error). The result is delivered on the returned channel exactly once.
func forwardClientToServer(src grpc.ClientStream, dst grpc.ServerStream) chan error {
	ret := make(chan error, 1)
	go func() {
		f := &rawFrame{}
		headerSent := false
		for {
			if err := src.RecvMsg(f); err != nil {
				ret <- err // io.EOF on clean upstream completion
				return
			}
			if !headerSent {
				// Relay upstream's response headers to the caller before the
				// first message. Header() blocks until upstream sends them,
				// which RecvMsg above guarantees has happened.
				headerSent = true
				h, err := src.Header()
				if err != nil {
					ret <- err
					return
				}
				if err := dst.SendHeader(h); err != nil {
					ret <- err
					return
				}
			}
			if err := dst.SendMsg(f); err != nil {
				ret <- err
				return
			}
		}
	}()
	return ret
}

func (p *Proxy) record(identity, tenant, tool, decision, reason string, start time.Time) {
	p.recorder.Record(identity, tenant, tool, decision, reason, "", p.now().Sub(start), start)
}

// remoteAddr returns the caller's network address for the audit trail, or ""
// if the peer isn't available (e.g. an in-process test connection).
func remoteAddr(ctx context.Context) string {
	if pr, ok := peer.FromContext(ctx); ok && pr.Addr != nil {
		return pr.Addr.String()
	}
	return ""
}
