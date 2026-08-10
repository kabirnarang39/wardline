package adapter_test

import (
	"sync"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/adapter"
	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryMeter_AddsAndReturnsRunningTotal(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	t1, err := m.Add("k", 30, time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 30, t1)
	t2, err := m.Add("k", 20, time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 50, t2)
}

func TestInMemoryMeter_KeysIndependent(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	_, _ = m.Add("a", 10, time.Now())
	total, _ := m.Add("b", 5, time.Now())
	assert.Equal(t, 5, total)
}

func TestInMemoryMeter_CurrentDoesNotAdd(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	total, err := m.Current("never-seen", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	_, _ = m.Add("k", 30, time.Now())
	total, _ = m.Current("k", time.Now())
	assert.Equal(t, 30, total)
	total, _ = m.Current("k", time.Now())
	assert.Equal(t, 30, total)
}

func TestInMemoryMeter_ConcurrentRaceFree(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.Add("k", 1, time.Now())
		}()
	}
	wg.Wait()
	total, _ := m.Add("k", 0, time.Now())
	assert.Equal(t, 50, total)
}

func TestInMemoryMeter_ListNearCeiling_SortsByTotalDescendingAndLimits(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	_, _ = m.Add("low", 1, time.Now())
	_, _ = m.Add("high", 30, time.Now())
	_, _ = m.Add("mid", 15, time.Now())

	got := m.ListNearCeiling(2)
	assert.Equal(t, []domain.Entry{{Key: "high", Total: 30}, {Key: "mid", Total: 15}}, got)
}

func TestInMemoryMeter_ListNearCeiling_NonPositiveLimitReturnsEmpty(t *testing.T) {
	m := adapter.NewInMemoryMeter()
	_, _ = m.Add("k", 5, time.Now())
	assert.Equal(t, []domain.Entry{}, m.ListNearCeiling(0))
	assert.Equal(t, []domain.Entry{}, m.ListNearCeiling(-1))
}
