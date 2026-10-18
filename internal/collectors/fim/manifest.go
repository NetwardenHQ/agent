package fim

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest is the on-disk baseline. A writable manifest is a tamperable
// baseline, so it is written owner-only and its ownership and permissions are checked on load
// (trust_*.go).
type Manifest struct {
	// ID changes whenever the baseline is rebuilt from scratch (first run, or
	// after the file was lost). An unexpected manifest_id with no legitimate
	// rebuild reason is the tamper/reset signal.
	ID string `json:"id"`

	// RulesetRev and Roots record what built this baseline. When either no
	// longer matches the running agent, the baseline is rebuilt with a stated
	// reason instead of being diffed into a storm of creates and deletes.
	RulesetRev int      `json:"ruleset_rev"`
	Roots      []string `json:"roots"`

	// Entries keyed by absolute path.
	Entries map[string]Entry `json:"entries"`

	// Unacked is what has been detected but not yet acknowledged by the
	// platform. Kept here, in the same atomic write as the baseline that
	// absorbed it, so a restart cannot separate the two.
	Unacked Unacked `json:"unacked"`
}

// Unacked is the part of the FIM report that must survive a failed post or an
// agent restart.
type Unacked struct {
	Changes []Change `json:"changes,omitempty"`
	// Dropped counts changes detected after Changes reached
	// maxPendingChanges. They are absorbed into the baseline but reported
	// only as a count.
	Dropped int `json:"dropped,omitempty"`
	// Rebuilt marks a baseline rebuild the platform has not yet seen.
	Rebuilt       bool   `json:"rebuilt,omitempty"`
	RebuildReason string `json:"rebuild_reason,omitempty"`
}

// manifestMode is the required permission: owner read/write only. Anything
// looser means another local account can read or rewrite the baseline.
const manifestMode = 0o600

// insecureModeMask matches any group or world permission bit, the same check
// applied to netwarden.conf. A readable manifest is loaded
// with a warning; a writable one is not trusted at all.
const insecureModeMask = 0o077

// errManifestUntrusted reports a manifest whose file or directory could have
// been written by an account other than root/SYSTEM/Administrators or the
// agent itself. Such a manifest is never diffed against: the baseline is
// rebuilt instead, with rebuild_reason "manifest_untrusted".
var errManifestUntrusted = errors.New("manifest is not trustworthy")

// newManifestID returns a fresh random identifier for a rebuilt baseline.
func newManifestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// loadManifest reads a manifest from disk. A missing file is not an error: it
// yields a nil manifest ("no baseline yet") and the collector builds a fresh
// one. A manifest that another account could have written
// returns errManifestUntrusted. A merely group/world-readable one is loaded,
// with insecure set so the caller can warn.
func loadManifest(path string) (*Manifest, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("opening manifest: %w", err)
	}
	defer f.Close()

	insecure, err := checkTrust(path, f)
	if err != nil {
		return nil, insecure, err
	}

	var m Manifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		// A corrupt manifest is treated as no baseline: rebuild rather than
		// diff against garbage (which would report every file as changed).
		return nil, insecure, fmt.Errorf("decoding manifest: %w", err)
	}
	if m.ID == "" {
		return nil, insecure, errors.New("decoding manifest: no id")
	}
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return &m, insecure, nil
}

// saveManifest writes a manifest atomically: a temp file in the same directory
// is written, fsynced, and renamed over the target. A crash mid-write can
// never leave a truncated baseline that would read as "everything changed".
func saveManifest(path string, m *Manifest) error {
	dir := filepath.Dir(path)
	if err := ensureStateDir(dir); err != nil {
		return fmt.Errorf("creating manifest dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".fim-manifest-*")
	if err != nil {
		return fmt.Errorf("creating temp manifest: %w", err)
	}
	tmpName := tmp.Name()
	// Removes the temp file on any return before the rename.
	defer os.Remove(tmpName)

	if err := tmp.Chmod(manifestMode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp manifest: %w", err)
	}

	enc := json.NewEncoder(tmp)
	if err := enc.Encode(m); err != nil {
		tmp.Close()
		return fmt.Errorf("encoding manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing manifest: %w", err)
	}
	if err := protectFile(tmpName); err != nil {
		return fmt.Errorf("protecting manifest: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming manifest into place: %w", err)
	}
	return nil
}
