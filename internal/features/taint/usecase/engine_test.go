package usecase

import (
	"testing"
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/taint/domain"
	platformsession "github.com/kabirnarang39/wardline/internal/platform/session"
	"github.com/stretchr/testify/assert"
)

var t0 = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

// fakeStore is a non-concurrent map store — enough for the single-goroutine
// engine unit tests. The real concurrent store is exercised in the adapter.
type fakeStore struct{ m map[string]domain.Label }

func newFakeStore() *fakeStore { return &fakeStore{m: map[string]domain.Label{}} }

func (s *fakeStore) Get(k string) (domain.Label, bool) { l, ok := s.m[k]; return l, ok }
func (s *fakeStore) Set(k string, l domain.Label)      { s.m[k] = l }
func (s *fakeStore) Clear(k string)                    { delete(s.m, k) }

func testCfg() domain.TaintConfig {
	return domain.TaintConfig{
		UntrustedSources:     []string{"web_fetch"},
		DeclassifySources:    []string{"human_approve"},
		TTLSeconds:           300,
		SessionWindowSeconds: 300,
	}
}

func entry(tool, decision string, ts time.Time) auditdomain.Entry {
	return auditdomain.Entry{Identity: "alice", Tenant: "acme", Tool: tool, Decision: decision, Timestamp: ts}
}

func sessionAt(now time.Time) string {
	return platformsession.SessionID("", "acme", "alice", now, 300)
}

func TestEngine_HeaderSessionSetReadAgree(t *testing.T) {
	e := NewEngine(testCfg(), newFakeStore(), func() time.Time { return t0 })
	// Untrusted read carrying an explicit session header on the entry.
	entry := auditdomain.Entry{Identity: "alice", Tenant: "acme", Tool: "web_fetch", Decision: "allow", Timestamp: t0, SessionID: "run-42"}
	e.Publish(entry)
	// The decision-time read uses the same explicit session id.
	assert.True(t, e.Current("acme", "alice", "run-42", t0).Tainted)
	// A different session id is NOT tainted (isolation).
	assert.False(t, e.Current("acme", "alice", "run-99", t0).Tainted)
}

func TestEngine_UntrustedReadTaints(t *testing.T) {
	e := NewEngine(testCfg(), newFakeStore(), func() time.Time { return t0 })
	e.Publish(entry("web_fetch", "allow", t0))
	assert.True(t, e.Current("acme", "alice", sessionAt(t0), t0).Tainted)
}

func TestEngine_TrustedReadDoesNotTaint(t *testing.T) {
	e := NewEngine(testCfg(), newFakeStore(), func() time.Time { return t0 })
	e.Publish(entry("read_file", "allow", t0))
	assert.False(t, e.Current("acme", "alice", sessionAt(t0), t0).Tainted)
}

func TestEngine_TaintExpiresAfterTTL(t *testing.T) {
	e := NewEngine(testCfg(), newFakeStore(), func() time.Time { return t0 })
	e.Publish(entry("web_fetch", "allow", t0))
	within := t0.Add(299 * time.Second)
	past := t0.Add(301 * time.Second)
	assert.True(t, e.Current("acme", "alice", sessionAt(t0), within).Tainted)
	assert.False(t, e.Current("acme", "alice", sessionAt(t0), past).Tainted)
}

func TestEngine_DeclassifyClearsTaint(t *testing.T) {
	e := NewEngine(testCfg(), newFakeStore(), func() time.Time { return t0 })
	e.Publish(entry("web_fetch", "allow", t0))
	assert.True(t, e.Current("acme", "alice", sessionAt(t0), t0).Tainted)
	e.Publish(entry("human_approve", "allow", t0))
	assert.False(t, e.Current("acme", "alice", sessionAt(t0), t0).Tainted)
}

func TestEngine_DeniedUntrustedCallNeverTaints(t *testing.T) {
	e := NewEngine(testCfg(), newFakeStore(), func() time.Time { return t0 })
	e.Publish(entry("web_fetch", "deny", t0))
	assert.False(t, e.Current("acme", "alice", sessionAt(t0), t0).Tainted)
}

// Label-creep guard: a realistic mixed sequence with TTL never leaves a
// permanently-tainted key. After the last untrusted read's TTL elapses (and
// with a declassify in the middle), the identity reads clean.
func TestEngine_NoPermanentTaint(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(testCfg(), store, func() time.Time { return t0 })

	// t0: untrusted read taints.
	e.Publish(entry("web_fetch", "allow", t0))
	// t0+10s: normal work, still tainted.
	assert.True(t, e.Current("acme", "alice", sessionAt(t0), t0.Add(10*time.Second)).Tainted)
	// t0+20s: human approves -> declassified.
	e.Publish(entry("human_approve", "allow", t0.Add(20*time.Second)))
	assert.False(t, e.Current("acme", "alice", sessionAt(t0), t0.Add(30*time.Second)).Tainted)

	// A later untrusted read re-taints, then simply ages out via TTL with no
	// further events — the key must not stay tainted forever.
	e.Publish(entry("web_fetch", "allow", t0.Add(40*time.Second)))
	sess := sessionAt(t0.Add(40 * time.Second))
	assert.True(t, e.Current("acme", "alice", sess, t0.Add(45*time.Second)).Tainted)
	assert.False(t, e.Current("acme", "alice", sess, t0.Add(400*time.Second)).Tainted)
}
