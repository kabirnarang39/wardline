package adapter_test

import (
	"strconv"
	"sync"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/taint/adapter"
	"github.com/kabirnarang39/wardline/internal/features/taint/domain"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryStore_AbsentKeyReturnsFalse(t *testing.T) {
	s := adapter.NewInMemoryStore()
	_, ok := s.Get("nope")
	assert.False(t, ok)
}

func TestInMemoryStore_SetGetClear(t *testing.T) {
	s := adapter.NewInMemoryStore()
	s.Set("k", domain.Label{Tainted: true})
	l, ok := s.Get("k")
	assert.True(t, ok)
	assert.True(t, l.Tainted)
	s.Clear("k")
	_, ok = s.Get("k")
	assert.False(t, ok)
}

// Run under -race: concurrent Set/Get/Clear must not race.
func TestInMemoryStore_ConcurrentAccessRaceFree(t *testing.T) {
	s := adapter.NewInMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := "k" + strconv.Itoa(i%8)
			s.Set(k, domain.Label{Tainted: true})
			_, _ = s.Get(k)
			s.Clear(k)
		}(i)
	}
	wg.Wait()
}
