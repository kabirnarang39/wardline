// Package reload provides a generic, lock-free atomic-swap holder for
// runtime-reloadable engines (policy matchers, RBAC authorizers, and
// similar read-mostly constructs this project builds via a pure
// constructor function). A reader calls Current() on every use (a
// single atomic load); a reload swaps the whole instance in one atomic
// store. There is no in-between state a concurrent reader can ever
// observe -- either the fully-old instance or the fully-new one.
package reload

import "sync/atomic"

// ReloadableEngine holds a swappable, read-mostly value. Swap does no
// validation of its own -- callers must have already fully constructed
// a valid *T (e.g. via the same constructor function used at process
// startup) before calling Swap; a construction failure must never reach
// Swap at all, so the previous value keeps serving untouched.
type ReloadableEngine[T any] struct {
	current atomic.Pointer[T]
}

func NewReloadableEngine[T any](initial *T) *ReloadableEngine[T] {
	r := &ReloadableEngine[T]{}
	r.current.Store(initial)
	return r
}

func (r *ReloadableEngine[T]) Current() *T { return r.current.Load() }

func (r *ReloadableEngine[T]) Swap(next *T) { r.current.Store(next) }
