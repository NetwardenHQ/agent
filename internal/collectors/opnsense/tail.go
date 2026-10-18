package opnsense

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// maxTailBytes bounds what one cycle reads from a log. A firewall under
	// scan can write megabytes a minute; if a cycle falls further behind than
	// this the oldest part is skipped and reported, never silently dropped.
	maxTailBytes = 16 << 20
	// maxLineBytes bounds one log line. Longer lines are skipped and counted
	// with the skipped bytes; no OPNsense log this collector reads comes close.
	maxLineBytes = 64 << 10
	// rolloverGrace is how long a daily log keeps being read after the day
	// changed, for lines syslog-ng was still writing to it at midnight.
	rolloverGrace = 10 * time.Minute
)

// dailyLog returns OPNsense's per-day log path:
// /var/log/<name>/<name>_YYYYMMDD.log (syslog-ng's local destination).
func dailyLog(dir, name string, t time.Time) string {
	return filepath.Join(dir, fmt.Sprintf("%s_%s.log", name, t.Format("20060102")))
}

// tailFile is the read position in one log file.
type tailFile struct {
	path   string
	info   os.FileInfo
	offset int64
	inLong bool // offset is inside a line longer than maxLineBytes
}

// tailer streams the complete lines appended to a log since its last call.
// The first call only records the end of the file: history from before the
// agent started is not replayed as if it had just happened.
type tailer struct {
	pathFor func(time.Time) string
	cur     tailFile
	prev    *tailFile // yesterday's daily log, read until prevEnd
	prevEnd time.Time
	primed  bool
	seen    bool // the log has existed at least once
}

func newTailer(pathFor func(time.Time) string) *tailer { return &tailer{pathFor: pathFor} }

// each calls fn for every new complete line and returns the number of bytes
// skipped (backlog beyond maxTailBytes, or over-long lines). fn must not keep
// the slice. measured is false when no interval could be measured: the first
// call (it only sets the baseline) or a log that has never existed. Callers
// must then emit nothing, not a zero.
func (t *tailer) each(now time.Time, fn func([]byte)) (skipped int64, measured bool, err error) {
	want := t.pathFor(now)
	if !t.primed {
		t.cur.path, t.primed = want, true
		st, serr := os.Stat(want)
		switch {
		case serr == nil:
			t.cur.info, t.cur.offset, t.seen = st, st.Size(), true
			return 0, false, nil
		case errors.Is(serr, os.ErrNotExist):
			return 0, false, nil
		default:
			t.primed = false
			return 0, false, serr
		}
	}
	var errs []error
	if want != t.cur.path {
		// Day rolled over: keep reading the old file for a while, start the
		// new one at 0.
		old := t.cur
		t.prev, t.prevEnd = &old, now.Add(rolloverGrace)
		t.cur = tailFile{path: want}
	}
	if t.prev != nil {
		s, perr := t.drain(t.prev, fn)
		skipped += s
		if perr != nil {
			errs = append(errs, perr)
		}
		if !now.Before(t.prevEnd) {
			t.prev = nil
		}
	}
	s, cerr := t.drain(&t.cur, fn)
	skipped += s
	if cerr != nil {
		errs = append(errs, cerr)
	}
	return skipped, t.seen, errors.Join(errs...)
}

func (t *tailer) drain(tf *tailFile, fn func([]byte)) (int64, error) {
	f, err := os.Open(tf.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	t.seen = true
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", tf.path)
	}
	// Rotated (new inode) or truncated: the new file's content is all new.
	if tf.info != nil && (!os.SameFile(tf.info, st) || st.Size() < tf.offset) {
		tf.offset, tf.inLong = 0, false
	}
	tf.info = st

	var skipped int64
	afterSkip := false
	if backlog := st.Size() - tf.offset; backlog > maxTailBytes {
		skipped = backlog - maxTailBytes
		tf.offset = st.Size() - maxTailBytes
		tf.inLong, afterSkip = false, true
	}
	if st.Size() == tf.offset {
		return skipped, nil
	}
	if _, err := f.Seek(tf.offset, io.SeekStart); err != nil {
		return skipped, err
	}
	// Read only up to the size seen above; what is appended meanwhile is
	// read next cycle.
	r := bufio.NewReaderSize(io.LimitReader(f, st.Size()-tf.offset), maxLineBytes)
	for {
		line, rerr := r.ReadSlice('\n')
		switch {
		case rerr == bufio.ErrBufferFull:
			// Too long: drop it, and the rest of it, whole.
			tf.inLong = true
			skipped += int64(len(line))
			tf.offset += int64(len(line))
			continue
		case rerr != nil:
			// EOF (or a read error) before a newline: a half-written
			// trailing line is read next cycle.
			if rerr == io.EOF {
				return skipped, nil
			}
			return skipped, rerr
		}
		tf.offset += int64(len(line))
		switch {
		case tf.inLong:
			tf.inLong = false
			skipped += int64(len(line))
		case afterSkip:
			// After a skip the first line is probably cut; drop it.
			afterSkip = false
			skipped += int64(len(line))
		default:
			fn(line[:len(line)-1])
		}
	}
}
