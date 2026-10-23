package spool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteEvents writes events as events/<name>.jsonl under the spool directory
// dir, for the agent's own collectors: the same contract and the same
// delivery as a local producer's events (docs/spool.md). It follows the
// producer rule, <name>.jsonl.tmp then rename, so the reader never sees a
// partial file, and it validates every event first: one that breaks the
// contract fails the whole write, rather than becoming a line the reader
// skips and counts.
func WriteEvents(dir, name string, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for i, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		if _, err := ParseEvent(line); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	evDir := filepath.Join(dir, "events")
	for _, d := range []string{dir, evDir} {
		if _, err := os.Lstat(d); err == nil {
			continue
		}
		if err := mkdirPrivate(d); err != nil {
			return err
		}
	}

	final := filepath.Join(evDir, name+".jsonl")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
