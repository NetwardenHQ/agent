package tripwire

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ctime cannot be set, so walks in these tests start at the real clock.
func makeFiles(t *testing.T, dir string, n int, content func(i int) []byte, name func(i int) string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, name(i)), content(i), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func text(int) []byte { return []byte(strings.Repeat("minutes of the meeting\n", 40)) }

func encrypted(int) []byte {
	b := make([]byte, 2048)
	_, _ = rand.Read(b)
	return b
}

// walkAt runs one walk as if it started at start.
func walkAt(t *testing.T, c *Collector, start time.Time) got {
	t.Helper()
	c.now = func() time.Time { return start }
	c.mu.Lock()
	delete(c.attempted, c.folders[0])
	c.mu.Unlock()
	return collect(t, c)
}

func TestWalkBaselineThenQuietThenBurst(t *testing.T) {
	e := newEnv(t)
	dir := e.path("data")
	makeFiles(t, dir, 50, text, func(i int) string { return fmt.Sprintf("doc%03d.txt", i) })
	c := e.collector(WithFolders([]string{dir}))

	// First walk: a baseline only.
	g := walkAt(t, c, time.Now())
	if v := g.one(t, "tripwire_files_total", map[string]string{"folder": dir}); v != 50 {
		t.Errorf("total = %v", v)
	}
	if len(g["tripwire_files_changed"]) != 0 {
		t.Errorf("the first walk reported changes")
	}

	// Quiet walks build history: nothing changed since they started.
	for i := 0; i < minHistory; i++ {
		g = walkAt(t, c, time.Now().Add(time.Minute))
		if v := g.one(t, "tripwire_files_changed", map[string]string{"folder": dir}); v != 0 {
			t.Fatalf("quiet walk %d changed = %v", i, v)
		}
	}

	// A burst: 300 files rewritten encrypted, plus a ransom note.
	before := time.Now().Add(-time.Second)
	c.mu.Lock()
	b := c.st.Folders[dir]
	b.LastWalkStart = before
	c.st.Folders[dir] = b
	c.mu.Unlock()
	makeFiles(t, dir, 300, encrypted, func(i int) string { return fmt.Sprintf("doc%03d.txt", i) })
	makeFiles(t, dir, 1, func(int) []byte { return []byte("send bitcoin") }, func(int) string { return "HOW_TO_DECRYPT.txt" })
	g = walkAt(t, c, time.Now())
	if v := g.one(t, "tripwire_change_spike", map[string]string{"folder": dir}); v != 1 {
		t.Errorf("burst not a spike")
	}
	if v := g.one(t, "tripwire_folders_change_spike", nil); v != 1 {
		t.Errorf("folders_change_spike = %v", v)
	}
	if v := g.one(t, "tripwire_suspicious_files", map[string]string{"folder": dir}); v != 301 {
		t.Errorf("suspicious = %v", v)
	}
	if len(g["tripwire_suspicious_file"]) != maxSuspects {
		t.Errorf("named %d suspects", len(g["tripwire_suspicious_file"]))
	}
	if g.one(t, "tripwire_suspicious_files_total", nil) != 301 {
		t.Errorf("total suspicious wrong")
	}
}

func TestOrdinaryChangesAreNotSuspicious(t *testing.T) {
	e := newEnv(t)
	dir := e.path("docs")
	makeFiles(t, dir, 5, text, func(i int) string { return fmt.Sprintf("n%d.md", i) })
	c := e.collector(WithFolders([]string{dir}))
	walkAt(t, c, time.Now())
	makeFiles(t, dir, 5, text, func(i int) string { return fmt.Sprintf("n%d.md", i) })
	c.mu.Lock()
	b := c.st.Folders[dir]
	b.LastWalkStart = time.Now().Add(-time.Second)
	c.st.Folders[dir] = b
	c.mu.Unlock()
	g := walkAt(t, c, time.Now())
	if v := g.one(t, "tripwire_files_changed", map[string]string{"folder": dir}); v != 5 {
		t.Errorf("changed = %v", v)
	}
	if v := g.one(t, "tripwire_suspicious_files", map[string]string{"folder": dir}); v != 0 {
		t.Errorf("edited notes flagged: %v", g["tripwire_suspicious_file"])
	}
	if v := g.one(t, "tripwire_change_spike", map[string]string{"folder": dir}); v != 0 {
		t.Errorf("five edits counted as a spike")
	}
}

func TestMassDeletionIsASpike(t *testing.T) {
	e := newEnv(t)
	dir := e.path("photos")
	makeFiles(t, dir, 600, text, func(i int) string { return fmt.Sprintf("p%04d.txt", i) })
	c := e.collector(WithFolders([]string{dir}))
	walkAt(t, c, time.Now())
	for i := 0; i < 400; i++ {
		if err := os.Remove(filepath.Join(dir, fmt.Sprintf("p%04d.txt", i))); err != nil {
			t.Fatal(err)
		}
	}
	g := walkAt(t, c, time.Now().Add(time.Minute))
	if v := g.one(t, "tripwire_change_spike", map[string]string{"folder": dir}); v != 1 {
		t.Errorf("two thirds of the folder deleted, no spike")
	}
}

func TestUnreadableFolder(t *testing.T) {
	e := newEnv(t)
	g := collect(t, e.collector(WithFolders([]string{e.path("no-such-share")})))
	if v := g.one(t, "tripwire_folder_readable", map[string]string{"folder": e.path("no-such-share")}); v != 0 {
		t.Errorf("readable = %v", v)
	}
	if v := g.one(t, "tripwire_folders_unreadable", nil); v != 1 {
		t.Errorf("folders_unreadable = %v", v)
	}
}

// A subfolder that becomes unreadable drops files from the count; that is
// not a mass deletion.
func TestUnreadableSubfolderIsNotADeletion(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	e := newEnv(t)
	dir := e.path("share")
	makeFiles(t, filepath.Join(dir, "sub"), 600, text, func(i int) string { return fmt.Sprintf("f%04d.txt", i) })
	makeFiles(t, dir, 10, text, func(i int) string { return fmt.Sprintf("top%d.txt", i) })
	c := e.collector(WithFolders([]string{dir}))
	walkAt(t, c, time.Now())
	if err := os.Chmod(filepath.Join(dir, "sub"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "sub"), 0o755) })
	g := walkAt(t, c, time.Now().Add(time.Minute))
	if v := g.one(t, "tripwire_change_spike", map[string]string{"folder": dir}); v != 0 {
		t.Errorf("an unreadable subfolder counted as a mass deletion")
	}
}

// A walk that runs past its deadline is discarded: neither its counts nor a
// new baseline are kept, and the folder reports the walk as incomplete.
func TestWalkDeadline(t *testing.T) {
	e := newEnv(t)
	dir := e.path("big")
	makeFiles(t, dir, 50, text, func(i int) string { return fmt.Sprintf("f%d.txt", i) })
	c := e.collector(WithFolders([]string{dir}))
	c.walkDeadline = time.Nanosecond
	g := walkAt(t, c, time.Now())
	if v := g.one(t, "tripwire_walk_complete", map[string]string{"folder": dir}); v != 0 {
		t.Errorf("a timed-out walk reported complete")
	}
	if len(g["tripwire_files_total"]) != 0 {
		t.Errorf("a timed-out walk reported a total")
	}
	c.mu.Lock()
	last := c.st.Folders[dir].LastWalkStart
	c.mu.Unlock()
	if !last.IsZero() {
		t.Errorf("a timed-out walk became the baseline")
	}
}

// A folder whose walk fails is retried on the walk interval, not every
// collection.
func TestFailedWalkWaitsForTheInterval(t *testing.T) {
	e := newEnv(t)
	dir := e.path("missing-share")
	walks := 0
	c := e.collector(WithFolders([]string{dir}))
	c.onWalk = func() { walks++ }
	now := time.Now()
	for i := 0; i < 5; i++ {
		c.now = func() time.Time { return now.Add(time.Duration(i) * time.Minute) }
		collect(t, c)
	}
	if walks != 1 {
		t.Errorf("walked %d times in five minutes", walks)
	}
	c.now = func() time.Time { return now.Add(16 * time.Minute) }
	collect(t, c)
	if walks != 2 {
		t.Errorf("not retried after the interval: %d", walks)
	}
}
