package usecase_test

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// TestConcurrencyStress_ProductionLikeMultiTenantTraffic is a
// production-shape test, not a severity benchmark: many goroutines
// (simulating many concurrent MCP client connections proxy/adapter.Handler
// would actually be serving), multiple tenants, dozens of identities per
// tenant, a mix of ordinary traffic and a handful of real attackers,
// every new heuristic this cycle added (drift_detection with H jitter,
// tenant_anomaly) turned on simultaneously -- run under `go test -race`
// so any data race in the new tenantState map or the new per-identity
// CUSUM fields under real concurrent load surfaces here, not in
// production. This is the closest thing to "real production traffic"
// achievable without an actual deployment: realistic concurrency,
// realistic identity/tenant cardinality, realistic mixed-traffic shape,
// sustained over many simulated windows.
func TestConcurrencyStress_ProductionLikeMultiTenantTraffic(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds:        60,
		RateSpikeEnabled:     true,
		RateMultiplier:       5,
		RateMinCalls:         10,
		NovelToolEnabled:     true,
		DenyRateSpikeEnabled: true,
		DenyRateThreshold:    0.5,
		DenyRateMinCalls:     10,
		MLScore:              domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0, MinCalls: 5},
		AutoBlock:            domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 8.0, BlockDurationSeconds: 300},
		Drift: domain.DriftConfig{
			Enabled: true, K: 0.5, H: 5.0, MinCalls: 5,
			HJitterFraction: 0.2,
			JitterSecret:    []byte("stress-test-secret-not-for-prod"),
		},
		TenantAnomaly: domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 5.0, MinCalls: 10},
	}

	clock := &atomicClock{}
	clock.set(time.Unix(0, 0))
	var writer raceCheckedWriter
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, &writer, nil, blocker, nil, clock.now, nil)

	const tenants = 5
	const identitiesPerTenant = 40
	const legitGoroutines = tenants * identitiesPerTenant
	const attackerGoroutines = 5 // a handful of real attackers mixed into otherwise-ordinary traffic
	const windowsToSimulate = 30
	tools := []string{"read_file", "list_dir", "stat", "search", "grep", "write_file"}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var publishCount int64

	// Legitimate concurrent traffic: every (tenant, identity) pair
	// publishes ordinary jittered calls on its own goroutine, the same
	// concurrency shape a real proxy handling many simultaneous agent
	// connections has -- Detector.Publish's own doc comment promises
	// exactly this ("must only stall the caller's own Publish, never
	// serialize every other identity's concurrent Publish calls behind
	// it"), so this test is that promise under real contention, not just
	// its doc comment.
	for tIdx := 0; tIdx < tenants; tIdx++ {
		for iIdx := 0; iIdx < identitiesPerTenant; iIdx++ {
			wg.Add(1)
			go func(tenant, identity string, seed int64) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(seed))
				for {
					select {
					case <-stop:
						return
					default:
					}
					d.Publish(auditdomain.Entry{
						Identity: identity,
						Tenant:   tenant,
						Tool:     tools[rng.Intn(len(tools))],
						Decision: "allow",
					})
					atomic.AddInt64(&publishCount, 1)
				}
			}(fmt.Sprintf("tenant-%d", tIdx), fmt.Sprintf("agent-%d-%d", tIdx, iIdx), int64(tIdx*1000+iIdx))
		}
	}

	// A handful of real attackers mixed in concurrently: abrupt spikes,
	// deny-rate spikes, and novel-tool bursts, all firing while the
	// legitimate goroutines above are also hammering the same Detector.
	for a := 0; a < attackerGoroutines; a++ {
		wg.Add(1)
		go func(tenant, identity string, seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for round := 0; round < 50; round++ {
				select {
				case <-stop:
					return
				default:
				}
				burst := 100 + rng.Intn(200)
				for c := 0; c < burst; c++ {
					d.Publish(auditdomain.Entry{
						Identity: identity,
						Tenant:   tenant,
						Tool:     fmt.Sprintf("attacker_tool_%d_%d", round, c%7),
						Decision: "allow",
					})
					atomic.AddInt64(&publishCount, 1)
				}
			}
		}(fmt.Sprintf("tenant-%d", a%tenants), fmt.Sprintf("attacker-%d", a), int64(90000+a))
	}

	// Clock-advancing goroutine: rolls simulated time forward while every
	// producer above is concurrently publishing -- exercises the real
	// race between window-rotation reads/writes (recordAndCheck's
	// windowJustCompleted branch) and ordinary in-window accumulation
	// happening on other goroutines at the same instant.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for w := 0; w < windowsToSimulate; w++ {
			time.Sleep(2 * time.Millisecond) // let producers get real work in before each rollover
			clock.add(time.Duration(cfg.WindowSeconds+1) * time.Second)
		}
		close(stop)
	}()

	wg.Wait()

	if publishCount == 0 {
		t.Fatal("expected concurrent producers to have published at least one entry")
	}
	t.Logf("concurrency stress: %d total Publish calls across %d legitimate + %d attacker goroutines over %d simulated windows, %d anomalies logged, no race detected",
		publishCount, legitGoroutines, attackerGoroutines, windowsToSimulate, writer.count())
}

// atomicClock is a thread-safe fakeClock -- fakeClock itself (detector_test.go)
// is deliberately not safe for concurrent mutation (every existing test
// using it is single-goroutine), so this stress test needs its own.
type atomicClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *atomicClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *atomicClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *atomicClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// raceCheckedWriter is domain.Writer, safe for concurrent Write calls
// (Detector.emit's own doc comment says Publish releases d.mu before
// calling it, specifically so concurrent identities' Writer.Write calls
// aren't serialized behind one lock -- this writer must itself be safe
// for that concurrency, or it would be the race, not Detector).
type raceCheckedWriter struct {
	mu sync.Mutex
	n  int
}

func (w *raceCheckedWriter) Write(domain.Anomaly) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n++
	return nil
}

func (w *raceCheckedWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}
