package agent

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// stateSpoolVersion is the spool feature level local producers check. Bump it
// when the spool contract gains a feature a producer can depend on.
const stateSpoolVersion = 1

// stateFileName is written next to the spool directory.
const stateFileName = "state.json"

// stateDirForOS is where state.json lives when no spool directory is set.
func stateDirForOS() string {
	switch runtime.GOOS {
	case "freebsd":
		return "/var/db/netwarden"
	case "linux":
		return "/var/lib/netwarden"
	}
	return ""
}

type stateSpool struct {
	Supported bool   `json:"supported"`
	Version   int    `json:"version"`
	Dir       string `json:"dir"`
}

// stateDoc is the contract's state.json, field for field.
type stateDoc struct {
	V                 int        `json:"v"`
	AgentVersion      string     `json:"agent_version"`
	StartedAt         string     `json:"started_at"`
	PID               int        `json:"pid"`
	Spool             stateSpool `json:"spool"`
	IntervalSeconds   int        `json:"interval_seconds"`
	LastPostAttemptAt *string    `json:"last_post_attempt_at"`
	LastPostOKAt      *string    `json:"last_post_ok_at,omitempty"`
	LastPostStatus    *int       `json:"last_post_status"`
	LastError         *string    `json:"last_error"`
	EventsSentTotal   int        `json:"events_sent_total"`
	EventsPending     int        `json:"events_pending"`
}

// stateFile keeps and persists the agent's state for local readers.
type stateFile struct {
	path   string
	logger *slog.Logger

	mu       sync.Mutex
	doc      stateDoc
	lastWarn string
}

// newStateFile returns nil when there is nowhere to write (unsupported OS and
// no spool directory).
func newStateFile(spoolDir, version string, started time.Time, logger *slog.Logger) *stateFile {
	dir := stateDirForOS()
	if spoolDir != "" {
		dir = filepath.Dir(spoolDir)
	}
	if dir == "" {
		return nil
	}
	return &stateFile{
		path:   filepath.Join(dir, stateFileName),
		logger: logger,
		doc: stateDoc{
			V:            1,
			AgentVersion: version,
			StartedAt:    started.UTC().Format(time.RFC3339),
			PID:          os.Getpid(),
			Spool:        stateSpool{Supported: spoolDir != "", Version: stateSpoolVersion, Dir: spoolDir},
		},
	}
}

// attempt describes one post attempt.
type attempt struct {
	At       time.Time
	Err      error
	Status   int // HTTP status, 0 when no reply arrived
	Interval time.Duration
	Sent     int
	Pending  int
}

// Update records the outcome and rewrites the file atomically.
func (s *stateFile) Update(a attempt) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := a.At.UTC().Format(time.RFC3339)
	s.doc.LastPostAttemptAt = &at
	if a.Status > 0 {
		st := a.Status
		s.doc.LastPostStatus = &st
	} else {
		s.doc.LastPostStatus = nil
	}
	if a.Err == nil {
		s.doc.LastPostOKAt = &at
		s.doc.LastError = nil
	} else {
		msg := a.Err.Error()
		s.doc.LastError = &msg
	}
	s.doc.IntervalSeconds = int(a.Interval.Seconds())
	s.doc.EventsSentTotal = a.Sent
	s.doc.EventsPending = a.Pending
	s.writeLocked()
}

// Init writes the file before the first post so readers see the agent at once.
func (s *stateFile) Init(interval time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doc.IntervalSeconds = int(interval.Seconds())
	s.writeLocked()
}

func (s *stateFile) writeLocked() {
	raw, err := json.Marshal(s.doc)
	if err == nil {
		err = writeAtomic(s.path, raw, 0o644)
	}
	if err != nil && err.Error() != s.lastWarn {
		s.lastWarn = err.Error()
		s.logger.Warn("could not write agent state file", "path", s.path, "error", err)
	} else if err == nil {
		s.lastWarn = ""
	}
}

// writeAtomic writes via a temporary file in the same directory and renames.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
