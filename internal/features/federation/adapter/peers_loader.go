package adapter

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

type peersFile struct {
	Peers []peerEntry `yaml:"peers"`
}

type peerEntry struct {
	ID            string `yaml:"id"`
	Endpoint      string `yaml:"endpoint"`
	PublicKeyFile string `yaml:"public_key_file"`
}

// LoadPeers loads and strictly decodes federation.peers_file, parsing
// each peer's public_key_file eagerly (at load time, not first use) so
// a malformed key is caught by wardline validate-config /
// wardline serve startup, not by the first inbound message that needs
// it. Strict decoding (KnownFields(true)) rejects an unrecognized key
// (e.g. a typo'd field name) rather than silently ignoring it -- the
// same fail-closed lesson RBAC's own design doc already learned the
// hard way about a typo silently promoting scope.
func LoadPeers(path string) ([]domain.Peer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read peers file %s: %w", path, err)
	}

	var pf peersFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("parse peers file %s: %w", path, err)
	}

	peers := make([]domain.Peer, 0, len(pf.Peers))
	for _, e := range pf.Peers {
		keyBytes, err := os.ReadFile(e.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read public key file %s for peer %s: %w", e.PublicKeyFile, e.ID, err)
		}
		pubKey, err := ParsePublicKeyPEM(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key file %s for peer %s: %w", e.PublicKeyFile, e.ID, err)
		}
		peers = append(peers, domain.Peer{ID: e.ID, Endpoint: e.Endpoint, PublicKey: pubKey})
	}
	return peers, nil
}
