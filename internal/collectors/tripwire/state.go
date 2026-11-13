package tripwire

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// canaryBaseline is what a canary looked like when first seen.
type canaryBaseline struct {
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"` // -1 when pinned and not yet seen intact
	FirstSeen time.Time `json:"first_seen"`
}

// folderBaseline is a protected folder's history.
type folderBaseline struct {
	LastWalkStart time.Time `json:"last_walk_start"`
	Total         int       `json:"total"`
	// Errors is how many entries the walk could not read; a total that drops
	// because a subfolder became unreadable is not a deletion.
	Errors int `json:"errors"`
	// History holds the changed-file counts of past walks, newest last.
	History []int `json:"history"`
}

// state is the tripwire's memory across restarts. Without it, a canary
// encrypted while the agent was stopped would become the new baseline.
type state struct {
	Canaries map[string]canaryBaseline `json:"canaries"`
	Folders  map[string]folderBaseline `json:"folders"`
}

func newState() *state {
	return &state{Canaries: map[string]canaryBaseline{}, Folders: map[string]folderBaseline{}}
}

func loadState(path string, logger *slog.Logger) *state {
	st := newState()
	if path == "" {
		return st
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("tripwire baseline unreadable; relearning", "path", path, "error", err)
		}
		return st
	}
	if err := json.Unmarshal(data, st); err != nil {
		logger.Warn("tripwire baseline is corrupt; relearning", "path", path, "error", err)
		return newState()
	}
	if st.Canaries == nil {
		st.Canaries = map[string]canaryBaseline{}
	}
	if st.Folders == nil {
		st.Folders = map[string]folderBaseline{}
	}
	return st
}

// save writes the state atomically, owner-only.
func (s *state) save(path string) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tripwire-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
