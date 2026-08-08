package adapter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"sort"

	anomalyadapter "github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/compliance/domain"
)

// bundleFile is one named byte blob destined for the tar.gz archive.
type bundleFile struct {
	name string
	data []byte
}

// WriteBundle serializes manifest, auditEntries, anomalies (optional),
// policySource, rbacSource (optional), and identities (optional) into a
// single gzip+tar stream written to w, in a fixed order (manifest.json,
// audit.jsonl, anomalies.jsonl, policy_snapshot, policy_backend.txt,
// rbac_snapshot, identities.json, checksums.txt[, checksums.txt.sig,
// public_key.pem]) so two exports of identical inputs produce
// byte-identical archives. "Identical inputs" includes manifest, whose
// GeneratedAt differs on every real run -- two live `wardline
// export-evidence` invocations over the same data are therefore NOT
// byte-identical, by design. The determinism here is what makes the
// bundle reproducible from a recorded Manifest and diffable in tests, not
// a promise that re-exporting yields the same bytes.
// audit.jsonl/anomalies.jsonl are serialized by
// reusing audit/adapter.JSONLWriter and anomaly/adapter.JSONLWriter
// directly (writing into an in-memory buffer instead of a file) so the
// bundle's wire format can never drift from what those existing types
// already produce.
//
// signingKey is optional (nil -- the default -- omits both
// checksums.txt.sig and public_key.pem, producing byte-for-byte the same
// unsigned bundle this function always produced). When non-nil,
// checksums.txt's own bytes are signed (RSA-PSS/SHA256, see signer.go) --
// since checksums.txt already covers every other file's integrity,
// signing it transitively authenticates the whole bundle without a
// second digest pass. identities is optional (nil/empty omits
// identities.json entirely, matching every other optional file's
// "omit, don't emit empty" convention already established for
// anomalies.jsonl/rbac_snapshot).
func WriteBundle(
	w io.Writer,
	manifest domain.Manifest,
	auditEntries []auditdomain.Entry,
	anomalies []anomalydomain.Anomaly,
	policySource []byte,
	policyBackend string,
	rbacSource []byte,
	identities []domain.RedactedIdentity,
	signingKey *rsa.PrivateKey,
) error {
	var files []bundleFile

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	files = append(files, bundleFile{"manifest.json", manifestJSON})

	var auditBuf bytes.Buffer
	auditWriter := auditadapter.NewJSONLWriter(&auditBuf)
	for _, e := range auditEntries {
		if err := auditWriter.Write(e); err != nil {
			return fmt.Errorf("marshal audit entry: %w", err)
		}
	}
	files = append(files, bundleFile{"audit.jsonl", auditBuf.Bytes()})

	if len(anomalies) > 0 {
		var anomalyBuf bytes.Buffer
		anomalyWriter := anomalyadapter.NewJSONLWriter(&anomalyBuf)
		for _, a := range anomalies {
			if err := anomalyWriter.Write(a); err != nil {
				return fmt.Errorf("marshal anomaly entry: %w", err)
			}
		}
		files = append(files, bundleFile{"anomalies.jsonl", anomalyBuf.Bytes()})
	}

	if len(policySource) > 0 {
		files = append(files, bundleFile{"policy_snapshot", policySource})
		// Omit rather than ship a file containing just a newline: an
		// auditor reading an empty policy_backend.txt would have no way to
		// tell "unknown backend" from "the file is broken". Config
		// validation defaults PolicyBackend to "yaml", so this is a
		// guard against a future caller, not a reachable path today.
		if policyBackend != "" {
			files = append(files, bundleFile{"policy_backend.txt", []byte(policyBackend + "\n")})
		}
	}

	if len(rbacSource) > 0 {
		files = append(files, bundleFile{"rbac_snapshot", rbacSource})
	}

	if len(identities) > 0 {
		identitiesJSON, err := json.MarshalIndent(identities, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal identities: %w", err)
		}
		files = append(files, bundleFile{"identities.json", identitiesJSON})
	}

	checksums := checksumsFile(files)
	files = append(files, bundleFile{"checksums.txt", checksums})

	if signingKey != nil {
		sig, err := Sign(checksums, signingKey)
		if err != nil {
			return fmt.Errorf("sign checksums: %w", err)
		}
		files = append(files, bundleFile{"checksums.txt.sig", sig})

		pubDER, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		files = append(files, bundleFile{"public_key.pem", pubPEM})
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{
			Name: f.name,
			Mode: 0600,
			Size: int64(len(f.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header for %s: %w", f.name, err)
		}
		if _, err := tw.Write(f.data); err != nil {
			return fmt.Errorf("write tar body for %s: %w", f.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	return nil
}

// checksumsFile produces a sha256sum-compatible listing ("<hex>  <name>")
// for every file already in the bundle -- an auditor (or CI) can verify
// the bundle with the standard `sha256sum -c checksums.txt`, no custom
// tooling required. Sorted by name for a deterministic, diffable output
// regardless of files' append order.
func checksumsFile(files []bundleFile) []byte {
	sorted := make([]bundleFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })

	var buf bytes.Buffer
	for _, f := range sorted {
		sum := sha256.Sum256(f.data)
		buf.WriteString(hex.EncodeToString(sum[:]))
		buf.WriteString("  ")
		buf.WriteString(f.name)
		buf.WriteString("\n")
	}
	return buf.Bytes()
}
