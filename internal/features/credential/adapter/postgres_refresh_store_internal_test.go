package adapter

import "testing"

// TestSplitIdentityKey_NegativePrefixFailsSafeInsteadOfPanicking is a
// regression test for a real crash: strconv.Atoi accepts a leading '-',
// so a bare identity string shaped like "-N:..." reached rest[prefixLen]
// with a negative index and panicked, instead of falling back to the
// bare-identity interpretation splitIdentityKey's own doc comment
// promises. postgresSafeKey never emits a negative prefix itself, but
// identity strings are unvalidated free-form text from JWT claims/SPIFFE
// IDs/preshared-secret config -- an operator-controlled or
// attacker-influenced identity of this shape must not crash the process
// on the next Redeem call that happens to decode it. This is a pure-
// function edge case with no live-Postgres dependency, unreachable
// through Issue+Redeem's own external-test-package coverage without a
// database, so it lives here rather than in postgres_refresh_store_test.go.
func TestSplitIdentityKey_NegativePrefixFailsSafeInsteadOfPanicking(t *testing.T) {
	cases := []string{
		"-1:x:y",
		"-2:xxxxxxxx:y",
		"-100:abcdef",
		"-1:",
	}
	for _, key := range cases {
		identity, tenantName := splitIdentityKey(key)
		if identity != key || tenantName != "" {
			t.Errorf("splitIdentityKey(%q) = (%q, %q), want (%q, \"\") -- must fail safe to the bare-identity interpretation", key, identity, tenantName, key)
		}
	}
}

// TestSplitIdentityKey_RoundTripsWithPostgresSafeKey proves the encode/
// decode pair are true inverses for the normal case, and that embedded
// colons in either tenant or identity don't break the length-prefixed
// split -- see postgresSafeKey's doc comment for why a colon-delimited
// split alone would be unsafe.
func TestSplitIdentityKey_RoundTripsWithPostgresSafeKey(t *testing.T) {
	cases := []struct{ tenant, identity string }{
		{"acme", "alice"},
		{"ac:me", "al:ice:x"},
		{"", "bob"}, // bare identity, no tenant prefix at all
	}
	for _, c := range cases {
		var key string
		if c.tenant == "" {
			key = c.identity
		} else {
			key = postgresSafeKey(c.tenant, c.identity)
		}
		gotIdentity, gotTenant := splitIdentityKey(key)
		if gotIdentity != c.identity || gotTenant != c.tenant {
			t.Errorf("splitIdentityKey(postgresSafeKey(%q, %q)) = (%q, %q), want (%q, %q)",
				c.tenant, c.identity, gotIdentity, gotTenant, c.identity, c.tenant)
		}
	}
}

// TestSplitIdentityKey_DigitPrefixLookingBareIdentityFallsBackSafely
// covers the brief's own worked example: a bare identity that happens to
// start with digits followed by a colon, but isn't a genuine
// length-prefixed key, must not be misparsed.
func TestSplitIdentityKey_DigitPrefixLookingBareIdentityFallsBackSafely(t *testing.T) {
	key := "123:notreallylength"
	identity, tenantName := splitIdentityKey(key)
	if identity != key || tenantName != "" {
		t.Errorf("splitIdentityKey(%q) = (%q, %q), want (%q, \"\")", key, identity, tenantName, key)
	}
}
