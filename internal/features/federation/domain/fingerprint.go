package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint derives a pseudonymous, deterministic identifier for an
// identity string, keyed by sharedSecret. Two instances in the same
// federation group (same shared secret) produce the same fingerprint
// for the same identity, so correlation across instances works; a
// party without the secret cannot reverse a fingerprint back to an
// identity (HMAC's standard one-wayness), and a different federation
// group (different secret) produces unrelated fingerprints for the
// same identity, so there is no cross-group linkability. Exact-match
// only, by design -- no wildcard or fuzzy identity grouping, matching
// this engine's existing exact-match posture in policy/usecase.Matcher.
func Fingerprint(identity string, sharedSecret []byte) string {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(identity))
	return hex.EncodeToString(mac.Sum(nil))
}
