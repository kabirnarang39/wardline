package adapter

import "testing"

// FuzzParseSCIMFilter guards the SCIM filter grammar's real attack
// surface: the `filter` query parameter on GET /scim/v2/Users and
// /scim/v2/Groups is untrusted, attacker-controlled input reaching a
// hand-written tokenizer + recursive-descent parser (filter.go's own
// doc comment) -- exactly the class of code where a malformed input
// causing a panic (index out of range, nil deref) or an infinite loop
// (unterminated recursion, a token-advance bug that never reaches EOF)
// is a real, remotely-triggerable denial-of-service, not a theoretical
// concern. Every existing TestParseSCIMFilter_* case seeds the corpus;
// the fuzzer's job is finding inputs those hand-picked cases didn't.
func FuzzParseSCIMFilter(f *testing.F) {
	seeds := []string{
		``,
		`userName eq "alice"`,
		`active eq true`,
		`active eq false`,
		`userName eq null`,
		`userName pr`,
		`userName co "ali"`,
		`userName sw "al"`,
		`userName ew "ce"`,
		`id gt 5`,
		`id lt 5`,
		`id ge 5`,
		`id le 5`,
		`userName eq "alice" and active eq true`,
		`userName eq "alice" or userName eq "bob"`,
		`not (active eq true)`,
		`(userName eq "alice" and active eq true) or userName eq "bob"`,
		`userName eq "unterminated`,
		`userName xyz "alice"`,
		`userName eq`,
		`and userName eq "alice"`,
		`(userName eq "alice"`,
		`userName eq "alice")`,
		`userName eq "alice" "bob"`,
		`123abc eq "alice"`,
		`((((((((((((((((((((`,
		`))))))))))))))))))))`,
		`not not not not not active eq true`,
		`userName eq "` + string(make([]byte, 200)) + `"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, filter string) {
		// The contract under fuzzing is narrower than correctness:
		// parseSCIMFilter must never panic and must always return
		// (terminate) regardless of input -- a well-formed filter's
		// actual evaluate() semantics are the existing table tests'
		// job, not this one's. recover() turns a panic into a t.Fatal
		// with the offending input attached, rather than the fuzzer's
		// own less-specific crash report.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSCIMFilter panicked on input %q: %v", filter, r)
			}
		}()
		_, _, _ = parseSCIMFilter(filter)
	})
}
