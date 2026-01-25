package certificatetransparency

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
)

const TileSize = 256

// TiledCheckpoint represents the checkpoint information from a tiled CT log
type TiledCheckpoint struct {
	Origin string
	Size   uint64
	Hash   string
}

// TileLeaf represents a single entry in a tile
type TileLeaf struct {
	Timestamp     uint64
	EntryType     uint16
	X509Entry     []byte // For X.509 certificates
	PrecertEntry  []byte // For precertificates
	Chain         [][]byte
	IssuerKeyHash [32]byte
}

// EncodeTilePath encodes a tile index into the proper path format
func EncodeTilePath(index uint64) string {
	if index == 0 {
		return "000"
	}

	// Collect 3-digit groups
	var groups []uint64
	for n := index; n > 0; n /= 1000 {
		groups = append(groups, n%1000)
	}

	// Build path from groups in reverse
	var b strings.Builder
	for i := len(groups) - 1; i >= 0; i-- {
		if i < len(groups)-1 {
			b.WriteByte('/')
		}
		if i > 0 {
			b.WriteByte('x')
		}
		fmt.Fprintf(&b, "%03d", groups[i])
	}

	return b.String()
}

// FetchCheckpoint fetches the checkpoint from a tiled CT log using the provided client
func FetchCheckpoint(ctx context.Context, client *http.Client, baseURL string) (*TiledCheckpoint, error) {
	url := fmt.Sprintf("%s/checkpoint", baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching checkpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checkpoint request failed with status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	lines := make([]string, 0, 3)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading checkpoint response: %w", err)
	}

	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid checkpoint format: expected at least 3 lines, got %d", len(lines))
	}

	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing tree size: %w", err)
	}

	return &TiledCheckpoint{
		Origin: lines[0],
		Size:   size,
		Hash:   lines[2],
	}, nil
}

// FetchTile fetches a tile from the tiled CT log using the provided client.
// If partialWidth > 0, fetches a partial tile with that width (1-255).
func FetchTile(ctx context.Context, client *http.Client, baseURL string, tileIndex uint64, partialWidth uint64) ([]TileLeaf, error) {
	tilePath := EncodeTilePath(tileIndex)
	if partialWidth > 0 {
		tilePath = fmt.Sprintf("%s.p/%d", tilePath, partialWidth)
	}
	url := fmt.Sprintf("%s/tile/data/%s", baseURL, tilePath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching tile %d: %w", tileIndex, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tile request failed with status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading tile data: %w", err)
	}

	return ParseTileData(data)
}

// ParseTileData parses the binary tile data into TileLeaf entries using cryptobyte
func ParseTileData(data []byte) ([]TileLeaf, error) {
	var leaves []TileLeaf
	s := cryptobyte.String(data)

	for !s.Empty() {
		var leaf TileLeaf

		if !s.ReadUint64(&leaf.Timestamp) || !s.ReadUint16(&leaf.EntryType) {
			return nil, fmt.Errorf("invalid data tile header")
		}

		switch leaf.EntryType {
		case 0: // x509_entry
			var cert cryptobyte.String
			var extensions, fingerprints cryptobyte.String
			if !s.ReadUint24LengthPrefixed(&cert) ||
				!s.ReadUint16LengthPrefixed(&extensions) ||
				!s.ReadUint16LengthPrefixed(&fingerprints) {
				return nil, fmt.Errorf("invalid data tile x509_entry")
			}
			leaf.X509Entry = append([]byte(nil), cert...)
			for !fingerprints.Empty() {
				var fp [32]byte
				if !fingerprints.CopyBytes(fp[:]) {
					return nil, fmt.Errorf("invalid fingerprints: truncated")
				}
				leaf.Chain = append(leaf.Chain, fp[:])
			}

		case 1: // precert_entry
			var issuerKeyHash [32]byte
			var defangedCrt, extensions, entry, fingerprints cryptobyte.String
			if !s.CopyBytes(issuerKeyHash[:]) ||
				!s.ReadUint24LengthPrefixed(&defangedCrt) ||
				!s.ReadUint16LengthPrefixed(&extensions) ||
				!s.ReadUint24LengthPrefixed(&entry) ||
				!s.ReadUint16LengthPrefixed(&fingerprints) {
				return nil, fmt.Errorf("invalid data tile precert_entry")
			}
			leaf.PrecertEntry = append([]byte(nil), defangedCrt...)
			leaf.IssuerKeyHash = issuerKeyHash
			for !fingerprints.Empty() {
				var fp [32]byte
				if !fingerprints.CopyBytes(fp[:]) {
					return nil, fmt.Errorf("invalid fingerprints: truncated")
				}
				leaf.Chain = append(leaf.Chain, fp[:])
			}

		default:
			return nil, fmt.Errorf("unknown entry type: %d", leaf.EntryType)
		}

		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

// ConvertTileLeafToRawLogEntry converts a TileLeaf to ct.RawLogEntry for compatibility
func ConvertTileLeafToRawLogEntry(leaf TileLeaf, index uint64) *ct.RawLogEntry {
	rawEntry := &ct.RawLogEntry{
		Index: int64(index),
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
		},
	}

	switch leaf.EntryType {
	case 0: // x509_entry
		// Use the DER certificate from X509Entry
		certData := leaf.X509Entry
		rawEntry.Leaf.TimestampedEntry = &ct.TimestampedEntry{
			Timestamp: leaf.Timestamp,
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: certData},
		}
		rawEntry.Cert = ct.ASN1Cert{Data: certData}

	case 1: // precert_entry
		// Build a minimal PreCert. TBSCertificate is the defanged TBS; IssuerKeyHash from tile.
		rawEntry.Leaf.TimestampedEntry = &ct.TimestampedEntry{
			Timestamp: leaf.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  leaf.IssuerKeyHash,
				TBSCertificate: leaf.PrecertEntry,
			},
		}

	default:
		// Unknown type; leave as zero-value
	}

	return rawEntry
}
