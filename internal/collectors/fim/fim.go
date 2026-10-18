// Package fim implements file integrity monitoring: it baselines a set of
// watched files by content hash and metadata, then reports what changes.
//
// This is the Tripwire idea (baseline, then diff), in a hybrid shape: an
// agent-side manifest gives cheap periodic change detection, and the roll-up
// digest shipped with each report lets the platform detect a manifest that was
// wiped or tampered (a reset shows up as a manifest_id change with
// baseline_rebuilt set; only ruleset_changed and roots_changed are benign
// rebuild reasons the agent can vouch for).
//
// Two layers feed the same baseline. A periodic walk, run in the background on
// its own time budget, is the reconcile and the catch-all. An optional
// fsnotify layer (watcher.go) re-checks individual paths between walks and
// reports them with detected="realtime". Either way, detected changes stay
// queued, in memory and in the manifest, until the post that carried them
// is acknowledged, so a failed send or a restart does not lose them.
//
// # Hashing
//
// SHA-256 from the standard library, not a third-party BLAKE3. A security
// agent shipped as a single trusted binary should minimize its crypto
// dependency surface; SHA-256 is stdlib, FIPS-friendly, and more than fast
// enough for hourly hashing of a bounded ruleset. The algorithm is recorded
// as a prefix on every hash ("sha256:...") so it can be swapped without
// breaking a stored baseline.
package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// hashPrefix tags every content hash with its algorithm, so a future change of
// algorithm is detectable in a stored manifest rather than silently comparing
// unlike hashes.
const hashPrefix = "sha256:"

// maxHashBytes caps how much of a single file is hashed. Watched files are
// configs and binaries; anything past this is not something FIM should be
// streaming through a hash on every cycle. A larger file is hashed over its
// first maxHashBytes and marked hash_truncated; its size is still compared in
// full, so growth or shrinkage is caught, but a same-size rewrite past the
// first maxHashBytes is not.
const maxHashBytes = 128 << 20 // 128 MiB

// errNotRegular reports that a path stopped being a regular file between the
// directory listing and the open (swapped for a symlink, FIFO or device).
var errNotRegular = errors.New("not a regular file")

// errReplaced reports that the file opened is not the one that was listed: a
// different regular file was renamed over it in between.
var errReplaced = errors.New("file replaced while being opened")

// ChangeKind classifies a detected change.
type ChangeKind string

const (
	ChangeCreated  ChangeKind = "created"  // present now, absent from the manifest
	ChangeModified ChangeKind = "modified" // content hash or size differs
	ChangeDeleted  ChangeKind = "deleted"  // in the manifest, gone now
	ChangeAttr     ChangeKind = "attr"     // content identical, mode/owner differs
)

// Detection sources, carried on every Change.
const (
	detectedWalk     = "periodic_walk"
	detectedRealtime = "realtime"
)

// Entry is one watched file's recorded state. It is serialized into the
// on-disk manifest, so its field names are a storage format.
//
// Mode, UID and GID are absent where the platform has no POSIX equivalent
// (Windows): a synthesized value would be reported as if it were real.
type Entry struct {
	Path string `json:"path"`
	// Hash is "sha256:<hex>". Empty only while the file has never been read;
	// a file that turns unreadable keeps its last known hash and is marked
	// Unreadable, so a read failure is not mistaken for a content change.
	Hash string `json:"hash,omitempty"`
	// HashTruncated marks a file larger than maxHashBytes, hashed over its
	// first maxHashBytes only.
	HashTruncated bool    `json:"hash_truncated,omitempty"`
	Unreadable    bool    `json:"unreadable,omitempty"`
	Mode          string  `json:"mode,omitempty"` // octal perm string, e.g. "0644"
	UID           *uint32 `json:"uid,omitempty"`
	GID           *uint32 `json:"gid,omitempty"`
	Size          int64   `json:"size"`
	MTime         int64   `json:"mtime"` // unix seconds
}

// Change is one detected difference between the manifest and the live host.
// UID and GID are pointers so that root (0) is reported rather than omitted.
type Change struct {
	Path          string     `json:"path"`
	Change        ChangeKind `json:"change"`
	Hash          string     `json:"hash,omitempty"`     // new content hash
	WasHash       string     `json:"was_hash,omitempty"` // prior hash from the manifest
	HashTruncated bool       `json:"hash_truncated,omitempty"`
	Unreadable    bool       `json:"unreadable,omitempty"` // new content could not be read
	Size          *int64     `json:"size,omitempty"`
	WasSize       *int64     `json:"was_size,omitempty"`
	Mode          string     `json:"mode,omitempty"`
	UID           *uint32    `json:"uid,omitempty"`
	GID           *uint32    `json:"gid,omitempty"`
	Detected      string     `json:"detected"` // "periodic_walk" | "realtime"
}

// ctxReader stops a long hash when the walk's budget runs out, rather than
// finishing a 128 MiB read the walk will discard anyway.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// hashFile hashes the regular file at path, opened without following a final
// symlink and without blocking on a FIFO (openNoFollow, per platform). The
// opened descriptor is checked against want (the Lstat taken when the path
// was listed), so a file swapped between the listing and the open is never
// hashed in its place. It returns the descriptor's own FileInfo, so the
// recorded metadata belongs to the bytes that were hashed.
func hashFile(ctx context.Context, path string, want os.FileInfo) (hash string, info os.FileInfo, truncated bool, err error) {
	f, err := openNoFollow(path)
	if err != nil {
		return "", nil, false, err
	}
	defer f.Close()

	info, err = f.Stat()
	if err != nil {
		return "", nil, false, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, false, errNotRegular
	}
	if want != nil && !os.SameFile(want, info) {
		return "", nil, false, errReplaced
	}

	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx, io.LimitReader(f, maxHashBytes)}); err != nil {
		return "", nil, false, err
	}
	return hashPrefix + hex.EncodeToString(h.Sum(nil)), info, info.Size() > maxHashBytes, nil
}

// recordFile builds an Entry for one regular file: content hash plus the
// metadata FIM treats as significant. It reports false when the path is no
// longer a regular file (or is gone), which callers treat the same as a walk
// that never saw it. A file that exists but cannot be read is recorded as
// Unreadable, with metadata from the listing.
func recordFile(ctx context.Context, path string, listed os.FileInfo) (Entry, bool) {
	hash, info, truncated, err := hashFile(ctx, path, listed)
	unreadable := false
	switch {
	case errors.Is(err, errNotRegular), errors.Is(err, fs.ErrNotExist):
		return Entry{}, false
	case err != nil:
		unreadable = true
		info = listed
	}
	mode, uid, gid := fileMeta(info)
	return Entry{
		Path:          path,
		Hash:          hash,
		HashTruncated: truncated,
		Unreadable:    unreadable,
		Mode:          mode,
		UID:           uid,
		GID:           gid,
		Size:          info.Size(),
		MTime:         info.ModTime().Unix(),
	}, true
}

// compareEntry decides what, if anything, changed for one path. cur may be
// adjusted: an unreadable file of unchanged size keeps its last known hash, so
// the baseline does not forget it and a later successful read is compared
// against the right value.
func compareEntry(old Entry, existed bool, cur *Entry, detected string) (Change, bool) {
	if !existed {
		return Change{
			Path: cur.Path, Change: ChangeCreated,
			Hash: cur.Hash, HashTruncated: cur.HashTruncated, Unreadable: cur.Unreadable,
			Size: ptr(cur.Size), Mode: cur.Mode, UID: cur.UID, GID: cur.GID,
			Detected: detected,
		}, true
	}
	if cur.Unreadable && cur.Size == old.Size {
		cur.Hash, cur.HashTruncated = old.Hash, old.HashTruncated
	}

	hashKnown := cur.Hash != "" && old.Hash != ""
	switch {
	case cur.Size != old.Size || (hashKnown && cur.Hash != old.Hash):
		return Change{
			Path: cur.Path, Change: ChangeModified,
			Hash: cur.Hash, WasHash: old.Hash, HashTruncated: cur.HashTruncated, Unreadable: cur.Unreadable,
			Size: ptr(cur.Size), WasSize: ptr(old.Size),
			Mode: cur.Mode, UID: cur.UID, GID: cur.GID,
			Detected: detected,
		}, true
	case cur.Mode != old.Mode || !sameID(cur.UID, old.UID) || !sameID(cur.GID, old.GID):
		// Content identical, metadata changed: a loosened mode on
		// /etc/shadow or a new owner on a binary leaves the bytes untouched.
		return Change{
			Path: cur.Path, Change: ChangeAttr,
			Hash: cur.Hash, WasHash: old.Hash, HashTruncated: cur.HashTruncated,
			Mode: cur.Mode, UID: cur.UID, GID: cur.GID,
			Detected: detected,
		}, true
	}
	return Change{}, false
}

func deletedChange(old Entry, detected string) Change {
	return Change{Path: old.Path, Change: ChangeDeleted, WasHash: old.Hash, WasSize: ptr(old.Size), Detected: detected}
}

// diff computes the changes from a manifest baseline to a freshly walked set.
// Both are keyed by path. A baseline path missing from current is reported
// deleted only if covered says the walk really looked where it would have
// been; otherwise it is carried into current unchanged (a capped walk or an
// unlistable directory is not evidence of deletion). Deterministic: changes
// are returned sorted by path.
func diff(baseline, current map[string]Entry, covered func(path string) bool) []Change {
	var changes []Change

	for path, cur := range current {
		old, existed := baseline[path]
		if ch, ok := compareEntry(old, existed, &cur, detectedWalk); ok {
			changes = append(changes, ch)
		}
		current[path] = cur
	}

	for path, old := range baseline {
		if _, stillThere := current[path]; stillThere {
			continue
		}
		if !covered(path) {
			current[path] = old
			continue
		}
		changes = append(changes, deletedChange(old, detectedWalk))
	}

	sortChanges(changes)
	return changes
}

// rollupDigest is the hash-of-hashes over the whole entry set: a single value
// the platform compares first, only diffing the full set when it disagrees.
// Order-independent by construction (entries are sorted by path before
// hashing), so two identical hosts produce the same digest.
func rollupDigest(entries map[string]Entry) string {
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		e := entries[p]
		// path, content hash, size, and the metadata FIM treats as significant.
		io.WriteString(h, p)
		h.Write([]byte{0})
		io.WriteString(h, e.Hash)
		h.Write([]byte{0})
		io.WriteString(h, strconv.FormatInt(e.Size, 10))
		h.Write([]byte{0})
		io.WriteString(h, e.Mode)
		h.Write([]byte{0})
		io.WriteString(h, idString(e.UID)+":"+idString(e.GID))
		h.Write([]byte{'\n'})
	}
	return hashPrefix + hex.EncodeToString(h.Sum(nil))
}

// cloneEntries returns a shallow copy of an entry map, for the real-time path
// to mutate without racing the published baseline.
func cloneEntries(m map[string]Entry) map[string]Entry {
	out := make(map[string]Entry, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortChanges orders changes by path for deterministic snapshots.
func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Path < cs[j].Path })
}

func ptr[T any](v T) *T { return &v }

func sameID(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func idString(id *uint32) string {
	if id == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*id), 10)
}

// normalizeRoots cleans, de-duplicates, and drops obviously bad root paths
// (empty, relative). FIM roots must be absolute: a relative root resolves
// against the agent's working directory, which is not a meaningful location.
// filepath.IsAbs is correct per-OS (a Windows "C:\..." is absolute; a bare
// "\foo" is not, matching Go's own rules).
func normalizeRoots(roots []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" || !filepath.IsAbs(r) {
			continue
		}
		clean := filepath.Clean(r)
		if _, dup := seen[clean]; dup {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}
