package tripwire

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	// maxChecked bounds how many changed files one walk opens to judge.
	maxChecked = 2000
	// maxSuspects bounds how many suspicious files are named.
	maxSuspects = 5
	// historyLen is how many past walks form the baseline (a day at 15 min).
	historyLen = 96
	// minHistory is how many walks are needed before a spike can be judged.
	minHistory = 8
	// spikeFactor and spikeFloor define a burst: more than spikeFactor times
	// the usual number of changed files, and at least spikeFloor of them.
	spikeFactor = 10
	spikeFloor  = 200
)

// skipDirs are DSM and macOS housekeeping folders whose churn means nothing.
var skipDirs = map[string]bool{"@eaDir": true, ".Spotlight-V100": true, ".fseventsd": true}

type suspect struct{ file, reason string }

type walkResult struct {
	readable     bool
	complete     bool
	baselineOnly bool
	total        int
	changed      int
	changedBytes int64
	spike        bool
	suspects     []suspect
	suspicious   int
	errors       int
}

// maybeWalk starts the walks that are due, in the background unless the
// collector runs them synchronously (tests).
func (c *Collector) maybeWalk(now time.Time) {
	c.mu.Lock()
	if c.walking {
		c.mu.Unlock()
		return
	}
	var due []string
	for _, f := range c.folders {
		if last, ok := c.attempted[f]; !ok || now.Sub(last) >= c.walkEvery {
			due = append(due, f)
			c.attempted[f] = now
		}
	}
	if len(due) == 0 {
		c.mu.Unlock()
		return
	}
	c.walking = true
	c.mu.Unlock()

	run := func() {
		for _, f := range due {
			r := c.walkFolder(f, now)
			c.mu.Lock()
			c.results[f] = r
			c.mu.Unlock()
		}
		c.mu.Lock()
		c.walking = false
		c.mu.Unlock()
	}
	if c.syncWalks {
		run()
	} else {
		go run()
	}
}

// walkFolder counts the files changed since the folder's previous walk and
// judges the changed ones. It never follows symlinks.
func (c *Collector) walkFolder(folder string, start time.Time) walkResult {
	c.mu.Lock()
	base := c.st.Folders[folder]
	c.mu.Unlock()
	if c.onWalk != nil {
		c.onWalk()
	}

	r := walkResult{baselineOnly: base.LastWalkStart.IsZero()}
	if _, err := os.ReadDir(folder); err != nil {
		return r
	}
	r.readable = true
	checked := 0
	deadline := time.Now().Add(c.walkDeadline)
	timedOut := false
	_ = filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
		if time.Now().After(deadline) {
			timedOut = true
			return fs.SkipAll
		}
		if err != nil {
			r.errors++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != folder && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			r.errors++
			return nil
		}
		r.total++
		if r.baselineOnly || changeTime(info).Before(base.LastWalkStart) {
			return nil
		}
		r.changed++
		r.changedBytes += info.Size()
		if checked >= maxChecked {
			return nil
		}
		checked++
		head, err := readHead(path)
		if err != nil {
			return nil
		}
		if why := suspicious(d.Name(), head); why != "" {
			r.suspicious++
			if len(r.suspects) < maxSuspects {
				rel, _ := filepath.Rel(folder, path)
				r.suspects = append(r.suspects, suspect{file: rel, reason: why})
			}
		}
		return nil
	})

	if timedOut {
		// Partial counts would read as a mass deletion; keep the old baseline.
		return walkResult{readable: true}
	}
	r.complete = true
	if !r.baselineOnly {
		r.spike = isSpike(r.changed, base.History) ||
			(base.Total > 0 && r.errors <= base.Errors && base.Total-r.total > max(spikeFloor, base.Total/5))
		base.History = append(base.History, r.changed)
		if len(base.History) > historyLen {
			base.History = base.History[len(base.History)-historyLen:]
		}
	}
	base.LastWalkStart = start
	base.Total = r.total
	base.Errors = r.errors
	c.mu.Lock()
	c.st.Folders[folder] = base
	c.mu.Unlock()
	return r
}

func isSpike(changed int, history []int) bool {
	if len(history) < minHistory {
		return false
	}
	h := append([]int(nil), history...)
	sort.Ints(h)
	usual := h[len(h)/2]
	return changed >= spikeFloor && changed > spikeFactor*usual
}

func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, headBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// emitWalks reports the latest walk of each folder.
func (c *Collector) emitWalks(e *emitter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	spikes, suspicious, unreadable := 0, 0, 0
	any := false
	for _, f := range c.folders {
		r, ok := c.results[f]
		if !ok {
			continue
		}
		any = true
		l := map[string]string{"folder": f}
		e.gauge("tripwire_folder_readable", b2f(r.readable), l)
		if !r.readable {
			unreadable++
			continue
		}
		e.gauge("tripwire_walk_complete", b2f(r.complete), l)
		if !r.complete {
			continue
		}
		e.gauge("tripwire_files_total", float64(r.total), l)
		if r.baselineOnly {
			continue
		}
		e.gauge("tripwire_files_changed", float64(r.changed), l)
		e.gauge("tripwire_bytes_changed", float64(r.changedBytes), l)
		e.gauge("tripwire_change_spike", b2f(r.spike), l)
		e.gauge("tripwire_suspicious_files", float64(r.suspicious), l)
		for _, s := range r.suspects {
			e.gauge("tripwire_suspicious_file", 1, map[string]string{"folder": f, "file": s.file, "reason": s.reason})
		}
		if r.spike {
			spikes++
		}
		suspicious += r.suspicious
	}
	if !any {
		return
	}
	e.gauge("tripwire_folders_change_spike", float64(spikes), nil)
	e.gauge("tripwire_suspicious_files_total", float64(suspicious), nil)
	e.gauge("tripwire_folders_unreadable", float64(unreadable), nil)
}
