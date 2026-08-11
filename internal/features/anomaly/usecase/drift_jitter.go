package usecase

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// driftEffectiveH returns identity's own perturbed decision threshold:
// cfg.H scaled by up to ±cfg.HJitterFraction, deterministically derived
// from HMAC-SHA256(cfg.JitterSecret, identity) -- the same
// never-inline, HMAC-keyed-by-a-per-deployment-secret pattern
// federation/domain.Fingerprint already uses (see its own doc comment).
// Deterministic per identity (not re-randomized every window): a value
// that changed on every call would average out to the unjittered mean
// over enough windows by the law of large numbers, giving an attacker
// who samples repeatedly no less certainty than no jitter at all. A
// value fixed per identity is what actually raises the cost of a
// static, source-derived attack -- see domain.DriftConfig's own doc
// comment for the honest limits of this (specifically: an *adaptive*
// attacker who can repeatedly probe the live system to infer the actual
// effective H for their own identity is not meaningfully slowed by
// this).
//
// Returns cfg.H unchanged when HJitterFraction <= 0 or JitterSecret is
// empty (config validation requires a non-empty secret whenever
// HJitterFraction > 0, but this stays safe standalone too -- an empty
// secret would make the HMAC, and so the "jitter," fully
// attacker-computable, which is providing the appearance of a defense
// with none of its substance).
func driftEffectiveH(identity string, cfg domain.DriftConfig) float64 {
	if cfg.HJitterFraction <= 0 || len(cfg.JitterSecret) == 0 {
		return cfg.H
	}
	mac := hmac.New(sha256.New, cfg.JitterSecret)
	mac.Write([]byte(identity))
	sum := mac.Sum(nil)
	// First 8 bytes as a uniform uint64, normalized to [0, 1) then
	// remapped to [-1, 1) -- same "take a hash, treat it as a uniform
	// random draw" technique consistent hashing/sharding schemes use,
	// just consuming fewer bits than a full 256-bit digest since 64 bits
	// of uniformity is far more precision than a ±fraction multiplier
	// needs.
	unit := float64(binary.BigEndian.Uint64(sum[:8])) / float64(^uint64(0))
	signed := unit*2 - 1
	return cfg.H * (1 + cfg.HJitterFraction*signed)
}
