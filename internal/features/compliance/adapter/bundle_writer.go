package adapter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// policySource, and rbacSource (optional) into a single gzip+tar stream
// written to w, in a fixed order (manifest.json, audit.jsonl,
// anomalies.jsonl, policy_snapshot, policy_backend.txt, rbac_snapshot,
// checksums.txt) so two exports of identical inputs produce
// byte-identical archives. audit.jsonl/anomalies.jsonl are serialized by
// reusing audit/adapter.JSONLWriter and anomaly/adapter.JSONLWriter
// directly (writing into an in-memory buffer instead of a file) so the
// bundle's wire format can never drift from what those existing types
// already produce.
func WriteBundle(
	w io.Writer,
	manifest domain.Manifest,
	auditEntries []auditdomain.Entry,
	anomalies []anomalydomain.Anomaly,
	policySource []byte,
	policyBackend string,
	rbacSource []byte,
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
		files = append(files, bundleFile{"policy_backend.txt", []byte(policyBackend + "\n")})
	}

	if len(rbacSource) > 0 {
		files = append(files, bundleFile{"rbac_snapshot", rbacSource})
	}

	files = append(files, bundleFile{"checksums.txt", checksumsFile(files)})

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
