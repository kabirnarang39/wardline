package adapter_test

import (
	"fmt"
	"testing"
	"time"

	anomalyadapter "github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// recordingWriterForTest is this file's own writer.Write fake -- the
// usecase package's own recordingWriter is unexported and lives in an
// internal test file, unreachable from this external (adapter_test)
// package.
type recordingWriterForTest struct {
	anomalies []domain.Anomaly
}

func (w *recordingWriterForTest) Write(a domain.Anomaly) error {
	w.anomalies = append(w.anomalies, a)
	return nil
}

// TestTenantAnomalyHA_CoordinatedSpikeSplitAcrossTwoRealReplicas is this
// whole plan's actual acceptance test: two real Detectors, each backed
// by its own real PostgresTenantWindowStore/PostgresTenantBaselineStore
// connections but pointed at the SAME database, simulating two HA
// replicas behind a load balancer that splits a coordinated attack's
// traffic in half. Neither replica's own local total should explain a
// detection; only the merged total read back from the shared database
// should. Real wall-clock sleeps against a short (2s) window --
// deliberate, not a fake clock, since the whole point is proving real
// Postgres TIMESTAMPTZ window-boundary arithmetic works against real
// elapsed time, not just in-process logic (see
// TestCheckTenantDrift_MergesAcrossTwoDetectors in the usecase package
// for the fake-store version of this same property).
func TestTenantAnomalyHA_CoordinatedSpikeSplitAcrossTwoRealReplicas(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	tenant := fmt.Sprintf("ha-test-tenant-%d", time.Now().UnixNano())

	newReplica := func(instanceID string) (*anomalyusecase.Detector, *recordingWriterForTest) {
		tws, err := anomalyadapter.NewPostgresTenantWindowStore(dsn, nil)
		if err != nil {
			t.Fatalf("NewPostgresTenantWindowStore: %v", err)
		}
		t.Cleanup(func() { _ = tws.Close() })
		tbs, err := anomalyadapter.NewPostgresTenantBaselineStore(dsn, instanceID, nil)
		if err != nil {
			t.Fatalf("NewPostgresTenantBaselineStore: %v", err)
		}
		t.Cleanup(func() { _ = tbs.Close() })

		cfg := domain.HeuristicConfig{
			WindowSeconds: 2,
			TenantAnomaly: domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 3.0, MinCalls: 5},
		}
		w := &recordingWriterForTest{}
		d := anomalyusecase.NewDetectorWithTenantStores(cfg, w, nil, nil, nil, time.Now, nil, tws, tbs)
		return d, w
	}

	replicaA, writerA := newReplica("integration-test-instance-a")
	replicaB, writerB := newReplica("integration-test-instance-b")

	// Both replicas publish ordinary, modest traffic for the same
	// tenant across several real-time windows, building a baseline both
	// replicas independently converge to via the fold-the-merged-total
	// mechanism.
	for w := 0; w < 10; w++ {
		for c := 0; c < 15; c++ {
			replicaA.Publish(auditdomain.Entry{Identity: fmt.Sprintf("a-%d", c), Tenant: tenant, Tool: "read_file", Decision: "allow"})
			replicaB.Publish(auditdomain.Entry{Identity: fmt.Sprintf("b-%d", c), Tenant: tenant, Tool: "read_file", Decision: "allow"})
		}
		time.Sleep(2100 * time.Millisecond)
	}

	// Attack window: each replica gets HALF the coordinated spike --
	// 150+150=300 combined, vs a ~30-call/window baseline. Neither
	// replica's own local 150 alone should look severe against that
	// baseline; only the merged 300 should.
	for c := 0; c < 150; c++ {
		replicaA.Publish(auditdomain.Entry{Identity: "a-attacker", Tenant: tenant, Tool: "read_file", Decision: "allow"})
		replicaB.Publish(auditdomain.Entry{Identity: "b-attacker", Tenant: tenant, Tool: "read_file", Decision: "allow"})
	}
	time.Sleep(2100 * time.Millisecond)
	replicaA.Publish(auditdomain.Entry{Identity: "probe", Tenant: tenant, Tool: "read_file", Decision: "allow"})
	replicaB.Publish(auditdomain.Entry{Identity: "probe", Tenant: tenant, Tool: "read_file", Decision: "allow"})

	found := false
	for _, a := range append(writerA.anomalies, writerB.anomalies...) {
		if a.Kind == domain.KindTenantDrift && a.Tenant == tenant {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the coordinated spike, split across two REAL replicas sharing a REAL Postgres database, to be detected via the merged total -- if this fails, the cross-replica merge is not actually working end to end")
	}
}
