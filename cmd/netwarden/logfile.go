package main

import (
	"os"
	"sync"
)

// logFile is the agent's log file, reopenable by path. A log rotator that
// renames the file (newsyslog on FreeBSD, logrotate without copytruncate)
// signals the agent, which reopens the path so new lines go to the new file
// instead of the renamed one.
//
// Every open, including a reopen, refuses a symlink at the final path
// component (openNoFollow) and creates the file 0640, so a link planted where
// the log will be (re)created cannot redirect root's appends elsewhere.
type logFile struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

// logFileMode is the mode a new log file is created with.
const logFileMode = 0o640

func openLogPath(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|openNoFollow, logFileMode)
}

func openLogFile(path string) (*logFile, error) {
	f, err := openLogPath(path)
	if err != nil {
		return nil, err
	}
	return &logFile{path: path, f: f}, nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Write(p)
}

// Reopen switches to a fresh handle on the path. On failure the current
// handle stays in use, so logging never stops.
func (l *logFile) Reopen() error {
	f, err := openLogPath(l.path)
	if err != nil {
		return err
	}
	l.mu.Lock()
	old := l.f
	l.f = f
	l.mu.Unlock()
	return old.Close()
}
