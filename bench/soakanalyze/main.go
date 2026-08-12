// Command soakanalyze reads bench/soak.sh's sample CSV
// (sample_unix_time,elapsed_seconds,goroutines,heap_inuse_bytes,rss_kb)
// and flags unbounded growth: a real leak grows roughly monotonically
// over the whole run, past GC's own sawtooth -- comparing the LAST
// quarter of samples' mean against the FIRST quarter's (post-warmup,
// skipping the very first samples where connection pools/caches are
// still filling) catches that growth trend without false-flagging
// normal GC variance between two adjacent samples.
//
// growthThreshold is deliberately generous (100%, i.e. more than
// doubling): the goal is catching an actual leak over 30-60 real
// minutes, not chasing normal allocator/scheduler variance with a tight
// threshold that flags every soak run as a false positive.
//
// Usage: soakanalyze <samples-csv>
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
)

const growthThreshold = 2.0 // last-quarter mean must not exceed 2x first-quarter mean

type sample struct {
	elapsedSeconds int
	goroutines     float64
	heapInuse      float64
	rssKB          float64
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: soakanalyze <samples-csv>")
		os.Exit(2)
	}
	samples, err := readSamples(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read samples:", err)
		os.Exit(1)
	}
	if len(samples) < 8 {
		fmt.Printf("only %d samples -- too few for a meaningful growth trend (need at least 8); treating as inconclusive, not a failure\n", len(samples))
		return
	}

	quarter := len(samples) / 4
	firstQuarter := samples[:quarter]
	lastQuarter := samples[len(samples)-quarter:]

	firstGoroutines, firstHeap, firstRSS := means(firstQuarter)
	lastGoroutines, lastHeap, lastRSS := means(lastQuarter)

	fmt.Printf("first quarter (t=%ds..%ds): goroutines=%.1f heap_inuse=%.0f rss_kb=%.0f\n",
		firstQuarter[0].elapsedSeconds, firstQuarter[len(firstQuarter)-1].elapsedSeconds, firstGoroutines, firstHeap, firstRSS)
	fmt.Printf("last quarter  (t=%ds..%ds): goroutines=%.1f heap_inuse=%.0f rss_kb=%.0f\n",
		lastQuarter[0].elapsedSeconds, lastQuarter[len(lastQuarter)-1].elapsedSeconds, lastGoroutines, lastHeap, lastRSS)

	failed := false
	if grew(firstGoroutines, lastGoroutines) {
		fmt.Printf("GOROUTINE LEAK SUSPECTED: %.1f -> %.1f (>%gx growth)\n", firstGoroutines, lastGoroutines, growthThreshold)
		failed = true
	}
	if grew(firstHeap, lastHeap) {
		fmt.Printf("HEAP GROWTH SUSPECTED: %.0f -> %.0f bytes (>%gx growth)\n", firstHeap, lastHeap, growthThreshold)
		failed = true
	}
	if grew(firstRSS, lastRSS) {
		fmt.Printf("RSS GROWTH SUSPECTED: %.0f -> %.0f KB (>%gx growth)\n", firstRSS, lastRSS, growthThreshold)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("SOAK CHECK PASSED: no unbounded goroutine/heap/RSS growth over the run")
}

func grew(first, last float64) bool {
	if first <= 0 {
		return false // avoid a division-by-zero false positive on a genuinely-zero baseline
	}
	return last > first*growthThreshold
}

func means(samples []sample) (goroutines, heap, rss float64) {
	var gSum, hSum, rSum float64
	var gCount, hCount, rCount int
	for _, s := range samples {
		if s.goroutines > 0 {
			gSum += s.goroutines
			gCount++
		}
		if s.heapInuse > 0 {
			hSum += s.heapInuse
			hCount++
		}
		if s.rssKB > 0 {
			rSum += s.rssKB
			rCount++
		}
	}
	if gCount > 0 {
		goroutines = gSum / float64(gCount)
	}
	if hCount > 0 {
		heap = hSum / float64(hCount)
	}
	if rCount > 0 {
		rss = rSum / float64(rCount)
	}
	return goroutines, heap, rss
}

func readSamples(path string) ([]sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("no data rows in %s", path)
	}

	samples := make([]sample, 0, len(rows)-1)
	for _, row := range rows[1:] { // skip header
		if len(row) != 5 {
			continue
		}
		elapsed, err := strconv.Atoi(row[1])
		if err != nil {
			continue
		}
		s := sample{elapsedSeconds: elapsed}
		s.goroutines, _ = strconv.ParseFloat(row[2], 64)
		s.heapInuse, _ = strconv.ParseFloat(row[3], 64)
		s.rssKB, _ = strconv.ParseFloat(row[4], 64)
		samples = append(samples, s)
	}
	return samples, nil
}
