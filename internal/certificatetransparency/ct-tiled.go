package certificatetransparency

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/trillian/client/backoff"
	"golang.org/x/crypto/cryptobyte"
)

const TileSize = 256

// tileKind identifies the kind of tile to fetch from a static CT log.
// Tiles of both kinds share the same index and width, they only differ in the
// path they are served under and in the encoding of their entries.
type tileKind string

const (
	tileKindData tileKind = "data"
)

// TiledCheckpoint represents the checkpoint information from a tiled CT log.
type TiledCheckpoint struct {
	Origin string
	Size   uint64
	Hash   string
}

// TileLeaf represents a single entry in a data tile.
type TileLeaf struct {
	Timestamp     uint64
	EntryType     uint16
	X509Entry     []byte // For X.509 certificates
	PrecertEntry  []byte // For precertificates
	Chain         [][]byte
	IssuerKeyHash [32]byte
}

// TileEntry is a single entry read from a tile, together with its index in the log.
type TileEntry struct {
	Index uint64
	Leaf *TileLeaf
}

// TileEntryHandler is called once for every entry read from a tile.
type TileEntryHandler func(TileEntry)

var (
	EntryTypeCert    uint16
	EntryTypePrecert uint16 = 1
)

// encodeTilePath encodes a tile index into the proper path format.
func encodeTilePath(index uint64) string {
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
	for i, v := range slices.Backward(groups) {
		if i < len(groups)-1 {
			builder.WriteByte('/')
		}

		if i > 0 {
			builder.WriteByte('x')
		}

		fmt.Fprintf(&builder, "%03d", v)
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
	if index > math.MaxInt64 {
		log.Printf("index (%d) exceeds math.MaxInt64, skipping\n", index)
		return nil
	}

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

// DefaultMaxPartialWait is the default maximum time to wait before forcefully
// fetching a partial tile that has not yet grown into a full tile.
const DefaultMaxPartialWait = 1 * time.Minute

type StaticCTClient struct {
	url        string
	httpClient *http.Client
	backoff    backoff.Backoff
	userAgent  string
	ctIndex    uint64

	// Deferred partial-tile state.
	// partialTileIndex holds the tile index of the currently tracked partial tile.
	// partialTileFirstSeen is when that partial tile was first observed; zero means
	// no partial tile is being tracked.
	partialTileIndex     uint64
	partialTileFirstSeen time.Time
	maxPartialWait       time.Duration
}

func NewStaticCTClient(url string, httpClient *http.Client, userAgent string, startIndex uint64) *StaticCTClient {
	return &StaticCTClient{
		url:        strings.TrimRight(url, "/"),
		httpClient: httpClient,
		backoff: backoff.Backoff{
			Min:    2 * time.Second,
			Max:    15 * time.Second,
			Factor: 1.3,
			Jitter: true,
		},
		userAgent:      userAgent,
		ctIndex:        startIndex,
		maxPartialWait: DefaultMaxPartialWait,
	}
}

// Monitor continuously monitors the tiled CT log for new entries, starting from the current ctIndex.
func (s *StaticCTClient) Monitor(ctx context.Context, handleEntry TileEntryHandler) error {
	for {
		hadNewEntries, err := s.fetchAndProcessTiles(ctx, handleEntry)
		if err != nil {
			log.Printf("Error processing tiled log updates for '%s': %s\n", s.url, err)
			return err
		}

		// Reset backoff if we found new entries
		if hadNewEntries {
			s.backoff.Reset()
		}

		select {
		case <-ctx.Done():
			ctxErr := ctx.Err()
			if ctxErr != nil {
				return fmt.Errorf("context error: %w", ctxErr)
			}

			return nil
		case <-time.After(s.backoff.Duration()):
			// Continue to the next iteration
		}
	}
}

// fetchAndProcessTiles checks for new entries in the tiled log and processes them.
// It returns true if at least one full tile was fetched.
func (s *StaticCTClient) fetchAndProcessTiles(ctx context.Context, handleEntry TileEntryHandler) (bool, error) {
	// Fetch current checkpoint
	checkpoint, fetchErr := s.FetchCheckpoint(ctx)
	if fetchErr != nil {
		return false, fmt.Errorf("fetching checkpoint: %w", fetchErr)
	}

	currentTreeSize := checkpoint.Size
	if currentTreeSize <= s.ctIndex {
		// No new entries
		return false, nil
	}

	// Process entries from current index to new tree size
	startTile := s.ctIndex / TileSize
	endTile := currentTreeSize / TileSize

	// Process full tiles
	fetchedFullTiles := false
	for tileIndex := startTile; tileIndex < endTile; tileIndex++ {
		if err := s.processTile(ctx, tileIndex, 0, handleEntry); err != nil {
			return false, fmt.Errorf("processing tile %d: %w", tileIndex, err)
		}

		fetchedFullTiles = true
	}

	// When the current end tile has advanced past the tracked partial tile, that tile
	// has since become a full tile and been processed; reset tracking so we start
	// fresh for the new partial tile (if any).
	if endTile > s.partialTileIndex {
		s.partialTileFirstSeen = time.Time{}
	}

	// Process partial tiles.
	partialSize := currentTreeSize % TileSize
	if partialSize > 0 {
		switch {
		case s.partialTileFirstSeen.IsZero() || s.partialTileIndex != endTile:
			// First time we see this partial tile – start the deferral clock.
			s.partialTileIndex = endTile
			s.partialTileFirstSeen = time.Now()

			// log.Println("Deferring fetch of partial tile", endTile, "with size", partialSize)

		case time.Since(s.partialTileFirstSeen) >= s.maxPartialWait:
			// The partial tile has been pending too long – fetch it now to prevent
			// extreme processing delays on slow-growing logs.
			if err := s.processTile(ctx, endTile, partialSize, handleEntry); err != nil {
				log.Printf("Warning: error processing partial tile %d: %s\n", endTile, err)
			}

			// Reset tracking; the tile will be re-observed on the next poll if it
			// still hasn't grown into a full tile.
			s.partialTileFirstSeen = time.Time{}

		default:
			// Still within the deferral window – skip.
		}
	} else {
		// currentTreeSize is an exact multiple of TileSize; no partial tile exists.
		s.partialTileFirstSeen = time.Time{}
	}

	return fetchedFullTiles, nil
}

// processTile processes a single tile from the tiled log.
// partialWidth of 0 means full tile, otherwise fetch partial tile with that width.
func (s *StaticCTClient) processTile(ctx context.Context, tileIndex, partialWidth uint64, handleEntry TileEntryHandler) error {
	entries, err := s.fetchTileEntries(ctx, tileIndex, partialWidth)
	if err != nil {
		return err
	}

	// Calculate the starting index for entries in this tile
	baseIndex := tileIndex * TileSize

	for i, entry := range entries {
		entry.Index = baseIndex + uint64(i)

		// Skip entries we've already processed
		if entry.Index < s.ctIndex {
			continue
		}

		handleEntry(entry)

		// Update the index
		s.ctIndex = entry.Index + 1
	}

	return nil
}

// fetchTileEntries fetches a single tile and parses it into TileEntry values.
// The Index field of the returned entries is relative to the tile and has to be
// offset by the caller.
func (s *StaticCTClient) fetchTileEntries(ctx context.Context, tileIndex, partialWidth uint64) ([]TileEntry, error) {
	data, err := s.fetchTile(ctx, tileKindData, tileIndex, partialWidth)
	if err != nil {
		return nil, fmt.Errorf("fetching tile: %w", err)
	}

	leaves, parseErr := ParseTileData(data)
	if parseErr != nil {
		return nil, fmt.Errorf("parsing data tile %d: %w", tileIndex, parseErr)
	}

	entries := make([]TileEntry, len(leaves))
	for i := range leaves {
		entries[i] = TileEntry{Leaf: &leaves[i]}
	}

	return entries, nil
}

// tileURL builds the URL of the given tile of the given kind.
// If partialWidth > 0, the URL points to a partial tile with that width (1-255).
func (s *StaticCTClient) tileURL(kind tileKind, tileIndex, partialWidth uint64) string {
	tilePath := encodeTilePath(tileIndex)

	if partialWidth > 0 {
		tilePath = fmt.Sprintf("%s.p/%d", tilePath, partialWidth)
	}

	return fmt.Sprintf("%s/tile/%s/%s", s.url, kind, tilePath)
}

// fetchTile fetches the raw body of a tile from the tiled CT log.
// If partialWidth > 0, fetches a partial tile with that width (1-255).
func (s *StaticCTClient) fetchTile(ctx context.Context, kind tileKind, tileIndex, partialWidth uint64) ([]byte, error) {
	url := s.tileURL(kind, tileIndex, partialWidth)

	req, newReqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if newReqErr != nil {
		return nil, fmt.Errorf("failed to create tile request: %w", newReqErr)
	}

	req.Header.Set("User-Agent", s.userAgent)

	resp, reqErr := s.httpClient.Do(req)
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

	return data, nil
}

// FetchCheckpoint fetches the checkpoint from a tiled CT log using the provided client.
func (s *StaticCTClient) FetchCheckpoint(ctx context.Context) (*TiledCheckpoint, error) {
	url := s.url + "/checkpoint"

	req, newReqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if newReqErr != nil {
		return nil, fmt.Errorf("failed to create checkpoint request: %w", newReqErr)
	}

	req.Header.Set("User-Agent", s.userAgent)

	resp, reqErr := s.httpClient.Do(req)
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
