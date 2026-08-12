// Command grpcload is a two-mode benchmark helper for the gRPC transport:
//
//	go run ./bench/grpcload upstream :39401
//	go run ./bench/grpcload load :38402 bench-agent 50 15s
//
// "upstream" runs a minimal raw-passthrough echo server standing in for
// the real upstream gRPC service Wardline fronts. "load" dials Wardline's
// own grpc_listen and fires <concurrency> workers for <duration>, each
// making back-to-back unary calls, reporting throughput and latency
// percentiles -- the gRPC-transport equivalent of the vegeta runs used
// for the HTTP proxy path (see bench/run.sh).
//
// It forces the same raw byte-passthrough codec Wardline's own gRPC
// transport uses (internal/features/grpcproxy/adapter/codec.go) so this
// tool needs no .proto file or generated stubs, matching the proxy it's
// benchmarking. Reimplemented here rather than imported: the codec is an
// unexported production type, and the codec itself is 15 lines.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const rawCodecName = "wardline-raw-proxy"

type rawFrame struct{ payload []byte }

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return v.(*rawFrame).payload, nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	f := v.(*rawFrame)
	f.payload = append(f.payload[:0], data...)
	return nil
}
func (rawCodec) Name() string { return rawCodecName }

const testMethod = "/bench.Echo/Call"

func echoHandler(_ any, ss grpc.ServerStream) error {
	f := &rawFrame{}
	if err := ss.RecvMsg(f); err != nil {
		return err
	}
	return ss.SendMsg(f)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "upstream":
		runUpstream(os.Args[2:])
	case "load":
		runLoad(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: grpcload upstream <listen-addr>")
	fmt.Fprintln(os.Stderr, "       grpcload load <target-addr> <identity> <concurrency> <duration> [bearer-token]")
	fmt.Fprintln(os.Stderr, "       (pass bearer-token when the target has credential_issuance on -- it no longer trusts a bare identity metadata value)")
	os.Exit(2)
}

func runUpstream(args []string) {
	if len(args) != 1 {
		usage()
	}
	lis, err := net.Listen("tcp", args[0])
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(echoHandler))
	log.Printf("grpcload upstream echoing on %s", args[0])
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func runLoad(args []string) {
	if len(args) != 4 && len(args) != 5 {
		usage()
	}
	target, identity := args[0], args[1]
	concurrency, err := strconv.Atoi(args[2])
	if err != nil {
		log.Fatalf("bad concurrency: %v", err)
	}
	duration, err := time.ParseDuration(args[3])
	if err != nil {
		log.Fatalf("bad duration: %v", err)
	}
	var bearerToken string
	if len(args) == 5 {
		bearerToken = args[4]
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var okCount, errCount int64
	latencies := make(chan time.Duration, 1<<20)
	deadline := time.Now().Add(duration)

	var wg sync.WaitGroup
	for range concurrency {
		wg.Go(func() {
			var ctx context.Context
			if bearerToken != "" {
				ctx = metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+bearerToken)
			} else {
				ctx = metadata.AppendToOutgoingContext(context.Background(), "x-wardline-identity", identity)
			}
			req := &rawFrame{payload: []byte("ping")}
			for time.Now().Before(deadline) {
				start := time.Now()
				resp := &rawFrame{}
				callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Invoke(callCtx, testMethod, req, resp)
				cancel()
				elapsed := time.Since(start)
				if err != nil {
					if atomic.AddInt64(&errCount, 1) == 1 {
						log.Printf("sample error: %v", err)
					}
				} else {
					atomic.AddInt64(&okCount, 1)
					latencies <- elapsed
				}
			}
		})
	}
	wg.Wait()
	close(latencies)

	all := make([]time.Duration, 0, len(latencies))
	for l := range latencies {
		all = append(all, l)
	}
	slices.Sort(all)

	total := okCount + errCount
	fmt.Printf("requests: %d (ok=%d err=%d)\n", total, okCount, errCount)
	fmt.Printf("throughput: %.1f req/s\n", float64(okCount)/duration.Seconds())
	if len(all) > 0 {
		fmt.Printf("latency p50=%v p95=%v p99=%v max=%v\n",
			percentile(all, 0.50), percentile(all, 0.95), percentile(all, 0.99), all[len(all)-1])
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
