package adapter_test

import (
	"fmt"
	"testing"
	"time"

	anomalyadapter "github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
)

// TestIdentityChurnHA_CoordinatedRotationSplitAcrossTwoRealReplicas
// mirrors TestTenantAnomalyHA_CoordinatedSpikeSplitAcrossTwoRealReplicas
// exactly, one signal down: two real Detectors, each backed by its own
// real PostgresChurnWindowStore/PostgresChurnBaselineStore connections
// but pointed at the SAME database, simulating two HA replicas behind a
// load balancer that splits a coordinated disposable-identity-rotation
// attack's traffic in half. Unlike tenant_anomaly's call-volume signal,
// identity_churn counts DISTINCT new identities, not raw calls -- so
// each replica's "half of the attack" here is its own set of distinct
// throwaway identities, not repeated calls from one identity. Real
// wall-clock sleeps against a short (2s) window, same reasoning as the
// tenant_anomaly HA test: proving real Postgres TIMESTAMPTZ
// window-boundary arithmetic against real elapsed time, not just
// in-process logic (see TestCheckIdentityChurn_MergesAcrossTwoDetectors
// in the usecase package for the fake-store version of this property).
func TestIdentityChurnHA_CoordinatedRotationSplitAcrossTwoRealReplicas(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	tenant := fmt.Sprintf("churn-ha-test-tenant-%d", time.Now().UnixNano())

	newReplica := func(instanceID string) (*anomalyusecase.Detector, *recordingWriterForTest) {
		// Each simulated replica gets its own connection pool -- real
		// replicas would too (pgpool.Open, called once per process in
		// cmd/wardline/main.go).
		db, err := pgpool.Open(dsn, 0)
		if err != nil {
			t.Fatalf("pgpool.Open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		cws, err := anomalyadapter.NewPostgresChurnWindowStore(db, nil)
		if err != nil {
			t.Fatalf("NewPostgresChurnWindowStore: %v", err)
		}
		cbs, err := anomalyadapter.NewPostgresChurnBaselineStore(db, instanceID, nil)
		if err != nil {
			t.Fatalf("NewPostgresChurnBaselineStore: %v", err)
		}

		cfg := domain.HeuristicConfig{
			WindowSeconds: 2,
			IdentityChurn: domain.IdentityChurnConfig{Enabled: true, RateMultiplier: 3.0, MinNewIdentities: 5},
		}
		w := &recordingWriterForTest{}
		d := anomalyusecase.NewDetector(cfg, w, nil, nil, nil, time.Now, nil).WithChurnStores(cws, cbs)
		return d, w
	}

	replicaA, writerA := newReplica("churn-integration-test-instance-a")
	replicaB, writerB := newReplica("churn-integration-test-instance-b")

	// Both replicas see ordinary, modest new-identity traffic for the
	// same tenant across several real-time windows, building a baseline
	// both replicas independently converge to via the
	// fold-the-merged-total mechanism -- 3 new identities per replica
	// per window (6 combined).
	newIdxA, newIdxB := 0, 0
	for w := 0; w < 10; w++ {
		for c := 0; c < 3; c++ {
			replicaA.Publish(auditdomain.Entry{Identity: fmt.Sprintf("a-organic-%d", newIdxA), Tenant: tenant, Tool: "read_file", Decision: "allow"})
			newIdxA++
			replicaB.Publish(auditdomain.Entry{Identity: fmt.Sprintf("b-organic-%d", newIdxB), Tenant: tenant, Tool: "read_file", Decision: "allow"})
			newIdxB++
		}
		time.Sleep(2100 * time.Millisecond)
	}

	// Attack window: each replica sees HALF a 60-disposable-identity
	// rotation burst -- 30+30=60 combined, vs a ~6-new-identity/window
	// baseline. Neither replica's own local 30 alone should look severe
	// against that baseline; only the merged 60 should.
	for c := 0; c < 30; c++ {
		replicaA.Publish(auditdomain.Entry{Identity: fmt.Sprintf("a-throwaway-%d", c), Tenant: tenant, Tool: "read_file", Decision: "allow"})
	}
	for c := 0; c < 30; c++ {
		replicaB.Publish(auditdomain.Entry{Identity: fmt.Sprintf("b-throwaway-%d", c), Tenant: tenant, Tool: "read_file", Decision: "allow"})
	}
	time.Sleep(2100 * time.Millisecond)
	replicaA.Publish(auditdomain.Entry{Identity: "probe-a", Tenant: tenant, Tool: "read_file", Decision: "allow"})
	replicaB.Publish(auditdomain.Entry{Identity: "probe-b", Tenant: tenant, Tool: "read_file", Decision: "allow"})

	found := false
	for _, a := range append(writerA.anomalies, writerB.anomalies...) {
		if a.Kind == domain.KindIdentityChurn && a.Tenant == tenant {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the coordinated disposable-identity rotation, split across two REAL replicas sharing a REAL Postgres database, to be detected via the merged total -- if this fails, the cross-replica merge is not actually working end to end")
	}
}
