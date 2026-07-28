package usecase

import "time"

// gc drops identityState entries whose lastSeen is more than 2x
// interval before now. Dropping an identity's state is safe: it simply
// reappears as "novel" on its next call (both the rate-spike baseline
// and the novel-tool set reset), which is the same conservative
// false-positive-over-false-negative posture as a process restart.
func (d *Detector) gc(now time.Time, interval time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := now.Add(-2 * interval)
	for identity, st := range d.state {
		if st.lastSeen.Before(cutoff) {
			delete(d.state, identity)
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
