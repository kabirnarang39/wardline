package reload

import (
	"errors"
	"testing"
)

func TestReloadCoordinator_UnknownDomainReturnsError(t *testing.T) {
	var audited []ReloadResult
	c := &ReloadCoordinator{
		Reloaders: map[string]func() error{},
		OnAudit:   func(r ReloadResult) { audited = append(audited, r) },
	}
	result := c.Reload("nonsense", "alice")
	if result.OK {
		t.Fatal("expected OK=false for an unknown domain")
	}
	if len(audited) != 1 {
		t.Fatalf("expected exactly 1 audited attempt, got %d", len(audited))
	}
}

func TestReloadCoordinator_SuccessfulReloadCallsOnAudit(t *testing.T) {
	var audited []ReloadResult
	c := &ReloadCoordinator{
		Reloaders: map[string]func() error{"policy": func() error { return nil }},
		OnAudit:   func(r ReloadResult) { audited = append(audited, r) },
	}
	result := c.Reload("policy", "bob")
	if !result.OK || result.AppliedBy != "bob" {
		t.Fatalf("got %+v, want OK=true AppliedBy=bob", result)
	}
	if len(audited) != 1 || !audited[0].OK {
		t.Fatalf("expected 1 successful audited attempt, got %+v", audited)
	}
}

func TestReloadCoordinator_FailedReloadStillCallsOnAudit(t *testing.T) {
	var audited []ReloadResult
	c := &ReloadCoordinator{
		Reloaders: map[string]func() error{"policy": func() error { return errors.New("bad yaml") }},
		OnAudit:   func(r ReloadResult) { audited = append(audited, r) },
	}
	result := c.Reload("policy", "carol")
	if result.OK {
		t.Fatal("expected OK=false")
	}
	if result.Error != "bad yaml" {
		t.Errorf("Error = %q, want %q", result.Error, "bad yaml")
	}
	if len(audited) != 1 {
		t.Fatalf("a REJECTED reload must still be audited -- got %d audit calls, want 1", len(audited))
	}
}
