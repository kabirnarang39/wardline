package usecase

import "time"

// GCBlocksOnce drops every block entry whose TTL elapsed before now.
// Exported (not a method) and taking now explicitly so tests can drive
// it deterministically -- StartBlockGC below is the real production
// entry point. This is memory hygiene for the map, entirely distinct
// from Check's own TTL-expiry logic, which doesn't depend on GC having
// run -- a Check call always compares live, GC just reclaims memory for
// identities that will never be checked again.
func GCBlocksOnce(b *BlockChecker, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for identity, e := range b.blocked {
		if !now.Before(e.until) {
			delete(b.blocked, identity)
		}
	}
}

// StartBlockGC runs GCBlocksOnce on a ticker until stop is closed.
// Intended to be launched in its own goroutine by the composition root
// (cmd/wardline/main.go), which owns closing stop on shutdown -- same
// shape as anomaly/usecase.StartGC.
func StartBlockGC(b *BlockChecker, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			GCBlocksOnce(b, now)
		}
	}
}
