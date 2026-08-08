package adapter

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadBundle opens the gzip+tar evidence bundle at path and returns every
// file's raw bytes keyed by name -- the read-side counterpart to
// WriteBundle, used by verify-evidence (and tests) rather than a fresh
// export path that never needs to read a bundle back.
func ReadBundle(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	files := make(map[string][]byte)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read tar entry %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = data
	}
	return files, nil
}

// VerifyChecksums parses checksums (the sha256sum-compatible "<hex>
// <two-space> <name>" format checksumsFile produces) and recomputes each
// listed file's SHA-256 against files, returning the names of every file
// that's missing or whose hash doesn't match. An empty result means
// every file checksums.txt lists is present and byte-identical to what
// was recorded at export time.
func VerifyChecksums(checksums []byte, files map[string][]byte) ([]string, error) {
	var mismatches []string
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed checksums.txt line: %q", line)
		}
		wantHex, name := parts[0], parts[1]
		data, ok := files[name]
		if !ok {
			mismatches = append(mismatches, name+" (missing from bundle)")
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != wantHex {
			mismatches = append(mismatches, name+" (checksum mismatch)")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan checksums.txt: %w", err)
	}
	return mismatches, nil
}

// unlistedByDesign are the bundle files that legitimately never appear in
// checksums.txt: checksums.txt itself (it can't hash its own final bytes),
// and the two signing artifacts, whose integrity is covered by the
// signature over checksums.txt rather than by a checksum line.
var unlistedByDesign = map[string]bool{
	"checksums.txt":     true,
	"checksums.txt.sig": true,
	"public_key.pem":    true,
}

// UnexpectedFiles returns every file present in the bundle that is neither
// listed in checksums.txt nor one of the by-design-unlisted files. A
// non-empty result means the bundle carries content outside its own
// integrity manifest -- checksum-and-signature verification alone would
// pass while an injected file rides along unverified, so verify-evidence
// treats this as a failure (a closed file-set, not just "listed files
// match").
func UnexpectedFiles(checksums []byte, files map[string][]byte) ([]string, error) {
	listed := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed checksums.txt line: %q", line)
		}
		listed[parts[1]] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan checksums.txt: %w", err)
	}
	var unexpected []string
	for name := range files {
		if listed[name] || unlistedByDesign[name] {
			continue
		}
		unexpected = append(unexpected, name)
	}
	return unexpected, nil
}
