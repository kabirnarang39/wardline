package reload

import (
	"sync"
	"testing"
)

func TestReloadableEngine_CurrentReturnsInitialValue(t *testing.T) {
	initial := 42
	r := NewReloadableEngine(&initial)
	if got := *r.Current(); got != 42 {
		t.Errorf("Current() = %d, want 42", got)
	}
}

func TestReloadableEngine_SwapReplacesCurrentValue(t *testing.T) {
	initial := 1
	r := NewReloadableEngine(&initial)
	next := 2
	r.Swap(&next)
	if got := *r.Current(); got != 2 {
		t.Errorf("Current() after Swap = %d, want 2", got)
	}
}

// TestReloadableEngine_ConcurrentReadsDuringSwap proves there is no
// window where a concurrent reader observes a torn/partial value --
// every read is either fully-old or fully-new, never anything else.
// Run with -race to catch any non-atomic access.
func TestReloadableEngine_ConcurrentReadsDuringSwap(t *testing.T) {
	initial := "old"
	r := NewReloadableEngine(&initial)

	var wg sync.WaitGroup
	seen := make(chan string, 1000)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				seen <- *r.Current()
			}
		}()
	}

	next := "new"
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.Swap(&next)
	}()

	wg.Wait()
	close(seen)

	for v := range seen {
		if v != "old" && v != "new" {
			t.Fatalf("observed torn value %q, want exactly \"old\" or \"new\"", v)
		}
	}
}
