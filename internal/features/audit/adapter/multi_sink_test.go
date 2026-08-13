package adapter_test

import (
	"reflect"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type recordingSink struct {
	entries []domain.Entry
}

func (s *recordingSink) Publish(e domain.Entry) {
	s.entries = append(s.entries, e)
}

func TestMultiSink_PublishReachesEveryMember(t *testing.T) {
	a := &recordingSink{}
	b := &recordingSink{}
	m := adapter.MultiSink{a, b}

	e := domain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"}
	m.Publish(e)

	if len(a.entries) != 1 || !reflect.DeepEqual(a.entries[0], e) {
		t.Errorf("expected sink a to receive the entry, got %+v", a.entries)
	}
	if len(b.entries) != 1 || !reflect.DeepEqual(b.entries[0], e) {
		t.Errorf("expected sink b to receive the entry, got %+v", b.entries)
	}
}

func TestMultiSink_NilMemberSkippedWithoutPanic(t *testing.T) {
	a := &recordingSink{}
	m := adapter.MultiSink{a, nil}

	e := domain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"}
	m.Publish(e) // must not panic

	if len(a.entries) != 1 {
		t.Errorf("expected the non-nil sink to still receive the entry, got %+v", a.entries)
	}
}

func TestMultiSink_ZeroMembersIsANoop(t *testing.T) {
	var m adapter.MultiSink
	m.Publish(domain.Entry{Identity: "alice"}) // must not panic
}
