package adapter_test

import (
	"sync"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/adapter"
	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryMeter_IncrementsAndReturnsRunningCount(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	c1, err := m.Increment("k", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 1, c1)
	c2, err := m.Increment("k", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 2, c2)
}

func TestInMemoryMeter_KeysIndependent(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	_, _ = m.Increment("a", time.Now())
	c, _ := m.Increment("b", time.Now())
	assert.Equal(t, 1, c)
}

func TestInMemoryMeter_ConcurrentRaceFree(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.Increment("k", time.Now())
		}()
	}
	wg.Wait()
	c, _ := m.Increment("k", time.Now())
	assert.Equal(t, 51, c)
}

func TestInMemoryMeter_CurrentDoesNotIncrement(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	c, err := m.Current("never-seen", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 0, c)

	_, _ = m.Increment("k", time.Now())
	_, _ = m.Increment("k", time.Now())
	c, err = m.Current("k", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 2, c)
	// Reading again must not change it.
	c, _ = m.Current("k", time.Now())
	assert.Equal(t, 2, c)
}

func TestInMemoryMeter_ListNearCeiling_SortsByCountDescendingAndLimits(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	_, _ = m.Increment("low", time.Now())
	for i := 0; i < 3; i++ {
		_, _ = m.Increment("high", time.Now())
	}
	for i := 0; i < 2; i++ {
		_, _ = m.Increment("mid", time.Now())
	}

	got := m.ListNearCeiling(2)
	assert.Equal(t, []domain.Entry{{Key: "high", Count: 3}, {Key: "mid", Count: 2}}, got)
}

func TestInMemoryMeter_ListNearCeiling_EmptyWhenNoCounts(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	assert.Empty(t, m.ListNearCeiling(10))
}

// A non-positive limit must return no entries, matching PostgresMeter's
// ListNearCeiling (Postgres rejects a negative LIMIT and zero legitimately
// returns no rows) -- the two Lister implementations must agree on this
// input even though this repo's only caller today always passes a positive
// constant.
func TestInMemoryMeter_ListNearCeiling_NonPositiveLimitReturnsEmpty(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	_, _ = m.Increment("k", time.Now())

	assert.Equal(t, []domain.Entry{}, m.ListNearCeiling(0))
	assert.Equal(t, []domain.Entry{}, m.ListNearCeiling(-1))
}
