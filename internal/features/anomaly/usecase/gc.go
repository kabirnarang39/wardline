package usecase

import (
	"fmt"
	"time"
)

// stalePruner is the optional extension a baselineStore may implement to
// delete rows left behind by an instance that no longer checkpoints (a
// permanently scaled-down replica, or one whose hostname changed and
// orphaned its old rows). Only the Postgres store implements it; the
// in-memory (nil-store) path never reaches the prune call below.
type stalePruner interface {
	PruneStale(olderThan time.Duration) (int64, error)
}

// abandonedInstancePruneFactor sets the prune cutoff at this many GC
// intervals: a baseline row not re-upserted in that long belongs to an
// instance that has stopped checkpointing entirely. It is deliberately
// well beyond the 2x-interval in-memory eviction window and tolerant of a
// couple of consecutively-failed checkpoints, so a live replica -- which
// re-upserts every one of its rows each tick -- can never have its own
// rows pruned out from under it.
const abandonedInstancePruneFactor = 4

// gc drops identityState entries whose lastSeen is more than 2x
// interval before now. Dropping an identity's state is safe: it simply
// reappears as "novel" on its next call (both the rate-spike baseline
// and the novel-tool set reset), which is the same conservative
// false-positive-over-false-negative posture as a process restart.
//
// This deliberately has no notion of whether an identity is currently
// auto-blocked: config validation rejects any
// anomaly.auto_block.block_duration_seconds greater than 2x
// anomaly.gc_interval_seconds, so a block always expires before its
// identity can go stale enough to be evicted. That keeps the "a blocked
// identity's baseline is frozen, not reset" guarantee intact without
// coupling Detector to BlockChecker.
func (d *Detector) gc(now time.Time, interval time.Duration) {
	d.mu.Lock()
	cutoff := now.Add(-2 * interval)
	var deletedKeys []string
	for key, st := range d.state {
		if st.lastSeen.Before(cutoff) {
			delete(d.state, key)
			// Collected under the same lock/pass that evicts the entry
			// from d.state, so the store's own row is deleted the same
			// tick -- otherwise an evicted identity's row survives in
			// Postgres indefinitely and LoadAll resurrects it (an
			// arbitrarily stale baseline) on the next restart instead of
			// the "novel" treatment eviction is supposed to guarantee.
			if d.store != nil {
				deletedKeys = append(deletedKeys, key)
			}
		}
	}

	var toSave map[string]IdentityStateSnapshot
	if d.store != nil {
		toSave = make(map[string]IdentityStateSnapshot, len(d.state))
		for key, st := range d.state {
			toSave[key] = snapshotIdentityState(st)
		}
	}
	d.mu.Unlock()

	// The snapshot map (and deletedKeys) are built while still holding
	// d.mu (a consistent point-in-time copy), then the lock is released
	// before this network call -- holding d.mu across a Postgres round
	// trip would block every concurrent Publish call for the duration of
	// the save, violating Publish's own non-blocking contract
	// transitively.
	if d.store != nil {
		if err := d.store.SaveAll(toSave, deletedKeys); err != nil && d.onError != nil {
			// Wrapped with a subsystem-identifying prefix: d.onError is
			// the same func(error) main.go's onAnomalyWriteErr uses for
			// actual anomaly-write failures, so an unwrapped error here
			// would log under that unrelated "anomaly write failed" line
			// -- an operator debugging a checkpoint-save failure would
			// grep the wrong subsystem name.
			d.onError(fmt.Errorf("anomaly baseline checkpoint save failed: %w", err))
		}
		// Clean up rows abandoned by instances that no longer checkpoint.
		// Runs after SaveAll so this tick's own upserts have already
		// refreshed every live row's updated_at -- only genuinely
		// abandoned rows can be older than the cutoff. Idempotent and
		// safe to run from every replica each tick (see
		// PostgresBaselineStore.PruneStale).
		if pruner, ok := d.store.(stalePruner); ok {
			if _, err := pruner.PruneStale(abandonedInstancePruneFactor * interval); err != nil && d.onError != nil {
				d.onError(fmt.Errorf("anomaly baseline stale-prune failed: %w", err))
			}
		}
	}
}

// StartGC runs Detector's GC on a ticker until stop is closed. Intended
// to be launched in its own goroutine by the composition root
// (cmd/wardline/main.go), which owns closing stop on shutdown.
func StartGC(d *Detector, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			d.gc(now, interval)
		}
	}
}
