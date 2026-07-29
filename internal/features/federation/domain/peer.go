package domain

import "crypto/rsa"

// Peer is one other Wardline instance this instance federates with,
// loaded from federation.peers_file. PublicKey verifies that peer's
// signature on inbound SignedSummaryBatch values -- it answers "did
// this peer send this message", a separate question from whether two
// instances' identity fingerprints are comparable (that's the shared
// HMAC secret, not this key).
type Peer struct {
	ID        string
	Endpoint  string
	PublicKey *rsa.PublicKey
}
