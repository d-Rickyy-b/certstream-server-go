package certificatetransparency

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
)

func Test_encodeTilePath(t *testing.T) {
	tests := []struct {
		name  string
		index uint64
		want  string
	}{
		{
			name:  "zero index",
			index: 0,
			want:  "000",
		},
		{
			name:  "single group padded",
			index: 1,
			want:  "001",
		},
		{
			name:  "single group max",
			index: 999,
			want:  "999",
		},
		{
			name:  "example from spec",
			index: 1_234_067,
			want:  "x001/x234/067",
		},
		{
			name:  "two groups exact thousand",
			index: 1_000,
			want:  "x001/000",
		},
		{
			name:  "two groups with remainder",
			index: 1_001,
			want:  "x001/001",
		},
		{
			name:  "two groups arbitrary",
			index: 123_456,
			want:  "x123/456",
		},
		{
			name:  "three groups",
			index: 1_000_000,
			want:  "x001/x000/000",
		},
		{
			name:  "four groups",
			index: 12_123_456_789,
			want:  "x012/x123/x456/789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeTilePath(tt.index)
			if got != tt.want {
				t.Errorf("encodeTilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

// fakeTiledLog serves a minimal static CT log (checkpoint and data tiles) and
// counts the requests it receives per path.
type fakeTiledLog struct {
	t        *testing.T
	mu       sync.Mutex
	size     uint64
	requests map[string]int
}

func newFakeTiledLog(t *testing.T, size uint64) (*fakeTiledLog, *httptest.Server) {
	t.Helper()

	l := &fakeTiledLog{t: t, size: size, requests: make(map[string]int)}
	srv := httptest.NewServer(l)
	t.Cleanup(srv.Close)

	return l, srv
}

func (l *fakeTiledLog) grow(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.size += n
}

func (l *fakeTiledLog) tileRequests() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	n := 0

	for path, count := range l.requests {
		if strings.HasPrefix(path, "/tile/") {
			n += count
		}
	}

	return n
}

func (l *fakeTiledLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.requests[r.URL.Path]++

	if r.URL.Path == "/checkpoint" {
		fmt.Fprintf(w, "example.com/log\n%d\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", l.size)
		return
	}

	tilePath, ok := strings.CutPrefix(r.URL.Path, "/tile/data/")
	if !ok {
		http.NotFound(w, r)
		return
	}

	width := uint64(TileSize)

	if base, p, found := strings.Cut(tilePath, ".p/"); found {
		tilePath = base

		var err error

		width, err = strconv.ParseUint(p, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}

	var tileIndex uint64

	for tileIndex = 0; encodeTilePath(tileIndex) != tilePath; tileIndex++ {
		if tileIndex > l.size/TileSize {
			http.NotFound(w, r)
			return
		}
	}

	first := tileIndex * TileSize
	if first+width > l.size || (width < TileSize && first+width != l.size) {
		http.NotFound(w, r)
		return
	}

	var b cryptobyte.Builder

	for i := first; i < first+width; i++ {
		b.AddUint64(i)             // timestamp, set to the index for easy checking
		b.AddUint16(EntryTypeCert) // entry type
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte{0x30, 0x00}) })
		b.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {})
		b.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {})
	}

	data, err := b.Bytes()
	if err != nil {
		l.t.Errorf("building tile: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	_, _ = w.Write(data)
}

// runPoll performs a single fetchAndProcessTiles call and returns the indexes
// of the entries it emitted.
func runPoll(t *testing.T, c *StaticCTClient) (indexes []uint64, hadNewEntries bool) {
	t.Helper()

	found := func(e *ct.RawLogEntry) {
		if uint64(e.Index) != e.Leaf.TimestampedEntry.Timestamp {
			t.Errorf("entry index %d does not match tile content %d", e.Index, e.Leaf.TimestampedEntry.Timestamp)
		}

		indexes = append(indexes, uint64(e.Index))
	}

	hadNewEntries, err := c.fetchAndProcessTiles(context.Background(), found, found)
	if err != nil {
		t.Fatalf("fetchAndProcessTiles: %v", err)
	}

	return indexes, hadNewEntries
}

func expectRange(t *testing.T, got []uint64, start, end uint64) {
	t.Helper()

	if uint64(len(got)) != end-start {
		t.Fatalf("got %d entries, want %d (indexes %v)", len(got), end-start, got)
	}

	for i, idx := range got {
		if idx != start+uint64(i) {
			t.Fatalf("entry %d has index %d, want %d", i, idx, start+uint64(i))
		}
	}
}

func TestStaticCTClient_NoRefetchWhenIdle(t *testing.T) {
	log, srv := newFakeTiledLog(t, 300)
	c := NewStaticCTClient(srv.URL, srv.Client(), "test", 0)
	// A partial tile is always deferred the first time it is observed, and
	// fetched on the next poll once the deferral window has expired.
	c.maxPartialWait = 0

	indexes, hadNewEntries := runPoll(t, c)
	expectRange(t, indexes, 0, 256)

	if !hadNewEntries {
		t.Error("first poll should report new entries")
	}

	indexes, _ = runPoll(t, c)
	expectRange(t, indexes, 256, 300)

	if c.ctIndex != 300 {
		t.Errorf("ctIndex = %d, want 300", c.ctIndex)
	}

	tileRequests := log.tileRequests()

	// The log has not grown: no tile should be fetched again, and no entry
	// should be emitted again.
	for range 3 {
		indexes, hadNewEntries = runPoll(t, c)
		expectRange(t, indexes, 0, 0)

		if hadNewEntries {
			t.Error("poll on an idle log should not report new entries")
		}
	}

	if got := log.tileRequests(); got != tileRequests {
		t.Errorf("idle polls fetched %d tiles, want 0", got-tileRequests)
	}
}

func TestStaticCTClient_StartAtCheckpointSize(t *testing.T) {
	log, srv := newFakeTiledLog(t, 300)
	c := NewStaticCTClient(srv.URL, srv.Client(), "test", 0)
	c.maxPartialWait = 0
	// Like runTiledWorker without recovery, start at the current tree size.
	c.ctIndex = 300

	indexes, _ := runPoll(t, c)
	expectRange(t, indexes, 0, 0)

	// The first new entry after startup must not be skipped. The partial tile
	// is deferred once, then fetched on the next poll.
	log.grow(1)
	runPoll(t, c)
	indexes, _ = runPoll(t, c)
	expectRange(t, indexes, 300, 301)

	log.grow(2)
	runPoll(t, c)
	indexes, _ = runPoll(t, c)
	expectRange(t, indexes, 301, 303)
}

func TestStaticCTClient_DeferPartialTiles(t *testing.T) {
	log, srv := newFakeTiledLog(t, 256)
	c := NewStaticCTClient(srv.URL, srv.Client(), "test", 256)

	// A new partial tile is observed but not fetched within the deferral window.
	log.grow(10)
	indexes, hadNewEntries := runPoll(t, c)
	expectRange(t, indexes, 0, 0)

	if hadNewEntries {
		t.Error("deferred partial should not report new entries")
	}

	if got := log.tileRequests(); got != 0 {
		t.Errorf("fetched %d tiles during deferral, want 0", got)
	}

	// Once the tile fills up, the full tile is fetched and every entry is
	// emitted exactly once.
	log.grow(246)
	indexes, hadNewEntries = runPoll(t, c)
	expectRange(t, indexes, 256, 512)

	if !hadNewEntries {
		t.Error("full tile fetch should report new entries")
	}

	if got := log.tileRequests(); got != 1 {
		t.Errorf("fetched %d tiles, want 1", got)
	}

	// When the deferral window expires, the partial is fetched once, and then
	// not again until the log grows.
	log.grow(5)
	runPoll(t, c) // starts the deferral clock
	c.partialTileFirstSeen = c.partialTileFirstSeen.Add(-2 * DefaultMaxPartialWait)
	indexes, _ = runPoll(t, c)
	expectRange(t, indexes, 512, 517)

	tileRequests := log.tileRequests()

	for range 3 {
		indexes, _ = runPoll(t, c)
		expectRange(t, indexes, 0, 0)
	}

	if got := log.tileRequests(); got != tileRequests {
		t.Errorf("idle polls fetched %d tiles, want 0", got-tileRequests)
	}
}
