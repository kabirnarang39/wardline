package adapter

import "testing"

func TestParseSCIMFilter_EmptyFilterIsUnfiltered(t *testing.T) {
	node, ok, err := parseSCIMFilter("")
	if err != nil || ok || node != nil {
		t.Fatalf("got (%v, %v, %v), want (nil, false, nil)", node, ok, err)
	}
}

func TestParseSCIMFilter_Operators(t *testing.T) {
	attrs := map[string]any{"userName": "alice", "active": true, "score": 42.0}
	cases := []struct {
		filter string
		want   bool
	}{
		{`userName eq "alice"`, true},
		{`userName eq "bob"`, false},
		{`userName ne "bob"`, true},
		{`userName co "lic"`, true},
		{`userName sw "al"`, true},
		{`userName ew "ce"`, true},
		{`userName sw "z"`, false},
		{`active eq true`, true},
		{`active eq false`, false},
		{`score gt 10`, true},
		{`score lt 10`, false},
		{`score ge 42`, true},
		{`score le 42`, true},
		{`userName pr`, true},
		{`missing pr`, false},
		{`userName EQ "alice"`, true}, // case-insensitive operator
	}
	for _, c := range cases {
		node, ok, err := parseSCIMFilter(c.filter)
		if err != nil {
			t.Errorf("filter %q: unexpected parse error: %v", c.filter, err)
			continue
		}
		if !ok {
			t.Errorf("filter %q: expected ok=true", c.filter)
			continue
		}
		if got := node.evaluate(attrs); got != c.want {
			t.Errorf("filter %q: got %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestParseSCIMFilter_LogicalOperatorsAndPrecedence(t *testing.T) {
	attrs := map[string]any{"userName": "alice", "active": true}
	cases := []struct {
		filter string
		want   bool
	}{
		{`userName eq "alice" and active eq true`, true},
		{`userName eq "bob" and active eq true`, false},
		{`userName eq "bob" or active eq true`, true},
		{`userName eq "bob" or active eq false`, false},
		{`not (active eq false)`, true},
		{`not active eq false`, true}, // "not" binds to the primary, same result without explicit parens
		// "and" binds tighter than "or": this reads as
		// (userName eq "bob" and active eq false) or (userName eq "alice"),
		// which is true because of the second disjunct, not because "or"
		// spans the whole expression left-to-right.
		{`userName eq "bob" and active eq false or userName eq "alice"`, true},
		{`(userName eq "alice" or userName eq "bob") and active eq true`, true},
	}
	for _, c := range cases {
		node, ok, err := parseSCIMFilter(c.filter)
		if err != nil || !ok {
			t.Errorf("filter %q: unexpected (ok=%v, err=%v)", c.filter, ok, err)
			continue
		}
		if got := node.evaluate(attrs); got != c.want {
			t.Errorf("filter %q: got %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestParseSCIMFilter_MalformedExpressions(t *testing.T) {
	cases := []string{
		`userName eq "unterminated`,
		`userName xyz "alice"`,
		`userName eq`,
		`and userName eq "alice"`,
		`(userName eq "alice"`,
		`userName eq "alice")`,
		`userName eq "alice" "bob"`,
		`123abc eq "alice"`, // an identifier can't start with a digit
	}
	for _, filter := range cases {
		if _, _, err := parseSCIMFilter(filter); err == nil {
			t.Errorf("filter %q: expected a parse error, got none", filter)
		}
	}
}

func TestParseSCIMFilter_PresentRequiresNonEmptyString(t *testing.T) {
	node, ok, err := parseSCIMFilter(`userName pr`)
	if err != nil || !ok {
		t.Fatalf("unexpected (ok=%v, err=%v)", ok, err)
	}
	if node.evaluate(map[string]any{"userName": ""}) {
		t.Error("expected `userName pr` to be false for an empty string value, not just present-as-a-key")
	}
	if !node.evaluate(map[string]any{"userName": "alice"}) {
		t.Error("expected `userName pr` to be true for a non-empty string value")
	}
}

func TestParseSCIMFilter_OrderedComparisonsIgnoreNonNumericTypes(t *testing.T) {
	// gt/lt/ge/le are only meaningful for numeric-valued attributes per
	// RFC 7644 -- a boolean or string attribute never matches, rather
	// than panicking on a type assertion or silently coercing.
	node, ok, err := parseSCIMFilter(`active gt 5`)
	if err != nil || !ok {
		t.Fatalf("unexpected (ok=%v, err=%v)", ok, err)
	}
	if node.evaluate(map[string]any{"active": true}) {
		t.Error("expected a boolean-valued attribute to never match an ordered comparison")
	}
}
