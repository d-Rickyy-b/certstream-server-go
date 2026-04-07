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

// TiledCheckpoint represents the checkpoint information from a tiled CT log.
type TiledCheckpoint struct {
	Origin string
	Size   uint64
	Hash   string
}

// TileLeaf represents a single entry in a tile.
type TileLeaf struct {
	Timestamp     uint64
	EntryType     uint16
	X509Entry     []byte // For X.509 certificates
	PrecertEntry  []byte // For precertificates
	Chain         [][]byte
	IssuerKeyHash [32]byte
}

// EncodeTilePath encodes a tile index into the proper path format.
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
	var builder strings.Builder
	for i := len(groups) - 1; i >= 0; i-- {
		if i < len(groups)-1 {
			builder.WriteByte('/')
		}

		if i > 0 {
			builder.WriteByte('x')
		}

		fmt.Fprintf(&builder, "%03d", groups[i])
	}

	return builder.String()
}

// FetchCheckpoint fetches the checkpoint from a tiled CT log using the provided client.
func FetchCheckpoint(ctx context.Context, client *http.Client, baseURL string) (*TiledCheckpoint, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	url := baseURL + "/checkpoint"

	req, newReqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if newReqErr != nil {
		return nil, fmt.Errorf("failed to create checkpoint request: %w", newReqErr)
	}

	req.Header.Set("User-Agent", UserAgent)

	resp, reqErr := client.Do(req)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to execute checkpoint request: %w", reqErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status code %d", ErrRequestFailed, resp.StatusCode)
	}

	lines := make([]string, 0, 3)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("failed reading response body: %w", scanErr)
	}

	if len(lines) < 3 {
		return nil, fmt.Errorf("%w: invalid checkpoint format: expected at least 3 lines, got %d", ErrCheckpointInvalidFormat, len(lines))
	}

	size, parseErr := strconv.ParseUint(lines[1], 10, 64)
	if parseErr != nil {
		return nil, fmt.Errorf("failed parsing tree size: %w", parseErr)
	}

	return &TiledCheckpoint{
		Origin: lines[0],
		Size:   size,
		Hash:   lines[2],
	}, nil
}

// FetchTile fetches a tile from the tiled CT log using the provided client.
// If partialWidth > 0, fetches a partial tile with that width (1-255).
func FetchTile(ctx context.Context, client *http.Client, baseURL string, tileIndex, partialWidth uint64) ([]TileLeaf, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	tilePath := EncodeTilePath(tileIndex)

	if partialWidth > 0 {
		tilePath = fmt.Sprintf("%s.p/%d", tilePath, partialWidth)
	}

	url := fmt.Sprintf("%s/tile/data/%s", baseURL, tilePath)

	req, newReqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if newReqErr != nil {
		return nil, fmt.Errorf("failed to create tile request: %w", newReqErr)
	}

	req.Header.Set("User-Agent", UserAgent)

	resp, reqErr := client.Do(req)
	if reqErr != nil {
		return nil, fmt.Errorf("fetching tile %d: %w", tileIndex, reqErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status code %d", ErrRequestFailed, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading tile data: %w", err)
	}

	return ParseTileData(data)
}

// ParseTileData parses the binary tile data into TileLeaf entries using cryptobyte.
func ParseTileData(data []byte) ([]TileLeaf, error) {
	var leaves []TileLeaf
	parser := cryptobyte.String(data)

	for !parser.Empty() {
		var leaf TileLeaf

		if !parser.ReadUint64(&leaf.Timestamp) || !parser.ReadUint16(&leaf.EntryType) {
			return nil, fmt.Errorf("header: %w", ErrInvalidDataTile)
		}

		switch leaf.EntryType {
		case 0: // x509_entry
			var cert cryptobyte.String
			var extensions, fingerprints cryptobyte.String

			if !parser.ReadUint24LengthPrefixed(&cert) ||
				!parser.ReadUint16LengthPrefixed(&extensions) ||
				!parser.ReadUint16LengthPrefixed(&fingerprints) {
				return nil, fmt.Errorf("x509_entry: %w", ErrInvalidDataTile)
			}

			leaf.X509Entry = append([]byte(nil), cert...)

			for !fingerprints.Empty() {
				var fp [32]byte
				if !fingerprints.CopyBytes(fp[:]) {
					return nil, ErrInvalidFingerprint
				}

				leaf.Chain = append(leaf.Chain, fp[:])
			}

		case 1: // precert_entry
			var issuerKeyHash [32]byte
			var defangedCrt, extensions, entry, fingerprints cryptobyte.String

			if !parser.CopyBytes(issuerKeyHash[:]) ||
				!parser.ReadUint24LengthPrefixed(&defangedCrt) ||
				!parser.ReadUint16LengthPrefixed(&extensions) ||
				!parser.ReadUint24LengthPrefixed(&entry) ||
				!parser.ReadUint16LengthPrefixed(&fingerprints) {
				return nil, fmt.Errorf("precert_entry: %w", ErrInvalidDataTile)
			}

			leaf.PrecertEntry = append([]byte(nil), defangedCrt...)
			leaf.IssuerKeyHash = issuerKeyHash

			for !fingerprints.Empty() {
				var fp [32]byte
				if !fingerprints.CopyBytes(fp[:]) {
					return nil, ErrInvalidFingerprint
				}

				leaf.Chain = append(leaf.Chain, fp[:])
			}

		default:
			return nil, fmt.Errorf("%w: %d", ErrUnknownEntryType, leaf.EntryType)
		}

		leaves = append(leaves, leaf)
	}

	return leaves, nil
}

// ConvertTileLeafToRawLogEntry converts a TileLeaf to ct.RawLogEntry for compatibility.
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
