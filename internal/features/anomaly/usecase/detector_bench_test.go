package usecase_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type bumpingClock struct{ t time.Time }

func (c *bumpingClock) now() time.Time { return c.t }

// BenchmarkDetector_Publish measures Detector.Publish's real per-call
// overhead on the request hot path -- the same "what does this actually
// cost" question BenchmarkDecider_Decide answers for policy decisions.
// Compares the pre-this-cycle heuristic set against every new heuristic
// this cycle added (drift_detection with both K/H jitter and the
// tool_diversity CUSUM, plus tenant_anomaly), so the real marginal cost
// of each is visible, not asserted. Run:
//
//	go test -bench=Detector_Publish -benchmem ./internal/features/anomaly/usecase
func BenchmarkDetector_Publish(b *testing.B) {
	baseCfg := domain.HeuristicConfig{
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
	}
	withDrift := baseCfg
	withDrift.Drift = domain.DriftConfig{Enabled: true, K: 0.5, H: 5.0, MinCalls: 5}
	withJitter := withDrift
	withJitter.Drift.HJitterFraction = 0.2
	withJitter.Drift.JitterSecret = []byte("benchmark-only-secret-do-not-use-in-prod")
	withTenant := withJitter
	withTenant.TenantAnomaly = domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 5.0, MinCalls: 10}
	withChurn := withTenant
	withChurn.IdentityChurn = domain.IdentityChurnConfig{Enabled: true, RateMultiplier: 3.0, MinNewIdentities: 5}

	cases := []struct {
		name string
		cfg  domain.HeuristicConfig
	}{
		{"baseline_no_drift_no_tenant", baseCfg},
		{"with_drift_detection", withDrift},
		{"with_drift_and_h_jitter", withJitter},
		{"with_drift_jitter_and_tenant_anomaly", withTenant},
		{"with_drift_jitter_tenant_and_identity_churn", withChurn},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			clock := &bumpingClock{t: time.Unix(0, 0)}
			d := usecase.NewDetector(tc.cfg, &discardWriter{}, nil, &discardBlocker{}, nil, clock.now, nil)
			tools := []string{"read_file", "list_dir", "stat", "search"}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d.Publish(auditdomain.Entry{
					Identity: fmt.Sprintf("agent-%d", i%50), // 50 concurrent identities, steady-state realistic cardinality
					Tenant:   fmt.Sprintf("tenant-%d", i%5), // 5 tenants
					Tool:     tools[i%len(tools)],
					Decision: "allow",
				})
				if i%30 == 0 { // roll the window roughly every 30 calls, matching this package's own recall-benchmark cadence
					clock.t = clock.t.Add(time.Duration(tc.cfg.WindowSeconds+1) * time.Second)
				}
			}
		})
	}
}

type discardWriter struct{}

func (discardWriter) Write(domain.Anomaly) error { return nil }

type discardBlocker struct{}

func (discardBlocker) Block(identity, tenantName, reason string) {}
