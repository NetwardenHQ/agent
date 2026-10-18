package selfupdate

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.0.0", "3.0.0", 0},
		{"2.0.0", "3.0.0", -1},
		{"3.0.0", "2.0.0", 1},
		// Numeric, not lexical: this is the one a string compare gets wrong.
		{"1.0.6", "1.0.10", -1},
		{"1.0.10", "1.0.6", 1},
		{"3.0", "3.0.0", 0},
		{"3", "3.0.1", -1},
		// A pre-release sorts before its release, both spellings.
		{"3.0.0~beta", "3.0.0", -1},
		{"3.0.0-beta", "3.0.0", -1},
		{"3.0.0", "3.0.0~beta", 1},
		{"3.0.0~beta", "2.9.9", 1},
		{"v3.0.0", "3.0.0", 0},
		// Unparseable compares equal rather than guessing.
		{"", "3.0.0", 0},
		{"unknown", "3.0.0", 0},
		{"3.0.0", "garbage", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestInWindow(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 9, 19, h, 30, 0, 0, time.Local) }

	// Ordinary window 01:00-05:00.
	for _, h := range []int{1, 2, 4} {
		if !inWindow(at(h), 1, 5) {
			t.Errorf("hour %d should be inside 1-5", h)
		}
	}
	for _, h := range []int{0, 5, 6, 13, 23} {
		if inWindow(at(h), 1, 5) {
			t.Errorf("hour %d should be outside 1-5", h)
		}
	}

	// A window that spans midnight, 22:00-03:00.
	for _, h := range []int{22, 23, 0, 2} {
		if !inWindow(at(h), 22, 3) {
			t.Errorf("hour %d should be inside 22-3", h)
		}
	}
	for _, h := range []int{3, 12, 21} {
		if inWindow(at(h), 22, 3) {
			t.Errorf("hour %d should be outside 22-3", h)
		}
	}

	// A degenerate window is never open, rather than always open.
	if inWindow(at(4), 4, 4) {
		t.Error("start == end should never be in window")
	}
}

// newTestUpdater builds an updater with a fixed clock on the host GOOS. Off
// Windows, ShouldApply refuses at the GOOS gate; windowsUpdater covers the
// Windows path.
func newTestUpdater(current string, hour int) *Updater {
	u := New(Config{Enabled: true, CurrentVersion: current, WindowStartHour: 1, WindowEndHour: 5},
		slog.New(slog.DiscardHandler))
	u.now = func() time.Time { return time.Date(2026, 9, 19, hour, 0, 0, 0, time.Local) }
	return u
}

func TestShouldApplyRefusesWhenDisabled(t *testing.T) {
	u := New(Config{Enabled: false, CurrentVersion: "1.0.0"}, slog.New(slog.DiscardHandler))
	if ok, reason := u.ShouldApply("3.0.0"); ok || reason != "self-update disabled" {
		t.Fatalf("got ok=%v reason=%q", ok, reason)
	}
}

func TestShouldApplyRefusesDowngradeAndSideways(t *testing.T) {
	u := newTestUpdater("3.0.0", 2)
	for _, offered := range []string{"2.0.0", "3.0.0", "1.0.6", "3.0.0~beta"} {
		ok, reason := u.ShouldApply(offered)
		if ok {
			t.Fatalf("offered %q against 3.0.0 should be refused", offered)
		}
		if reason != "offered version is not newer" && reason != "self-update only implemented on windows" {
			t.Fatalf("offered %q: unexpected reason %q", offered, reason)
		}
	}
}

func TestShouldApplyRefusesEmptyVersion(t *testing.T) {
	u := newTestUpdater("1.0.0", 2)
	if ok, _ := u.ShouldApply(""); ok {
		t.Fatal("empty version must never be applied")
	}
}

func TestShouldApplyRefusesGarbageVersion(t *testing.T) {
	// Unparseable compares equal, so it is "not newer" and refused.
	u := newTestUpdater("1.0.0", 2)
	for _, junk := range []string{"latest", "../../evil", "9.9.9; rm -rf /"} {
		if ok, _ := u.ShouldApply(junk); ok {
			t.Fatalf("junk version %q must never be applied", junk)
		}
	}
}

func TestShouldApplyRespectsWindowAndBackoff(t *testing.T) {
	// Outside the window. Off Windows the GOOS gate refuses first; either way
	// the update must not proceed.
	if ok, _ := newTestUpdater("1.0.0", 13).ShouldApply("3.0.0"); ok {
		t.Fatal("must not apply outside the maintenance window")
	}

	u := newTestUpdater("1.0.0", 2)
	u.lastAttempt["3.0.0"] = u.now().Add(-1 * time.Hour)
	if ok, _ := u.ShouldApply("3.0.0"); ok {
		t.Fatal("must not retry a version attempted an hour ago")
	}

	u2 := newTestUpdater("1.0.0", 2)
	u2.inProgress = true
	if ok, _ := u2.ShouldApply("3.0.0"); ok {
		t.Fatal("must not start a second update while one is running")
	}
}

func TestHandleHintDoesNotActWhenRefused(t *testing.T) {
	u := newTestUpdater("3.0.0", 2)
	u.apply = func(context.Context, Target, []string, *slog.Logger) error {
		t.Error("apply must not be reached for a refused hint")
		return nil
	}
	// A scheduled update would set inProgress.
	u.HandleHint(Offer{Version: "1.0.0"})
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.inProgress {
		t.Fatal("a refused hint must not start an update")
	}
}

func TestSafeVersionRejectsInjection(t *testing.T) {
	bad := []string{
		"", "   ", "abc", "..", "3.0.0/../../evil", "3.0.0/../x",
		"../../../etc/passwd", "3.0.0 && calc.exe", "3.0.0;rm -rf /",
		"3.0.0\nX", "3.0.0\x00", "3.0.0?x=1", "3.0.0#frag", "3.0.0%2e%2e",
		"http://evil.test/x.exe", "\\\\evil\\share\\x.exe",
		strings.Repeat("9", 33),
	}
	for _, v := range bad {
		if safeVersion(v) {
			t.Errorf("safeVersion(%q) should be false", v)
		}
	}

	for _, v := range []string{"3.0.0", "3.0.1", "10.2.30", "3.0.0-beta", "3.0.0~beta1", "3.0"} {
		if !safeVersion(v) {
			t.Errorf("safeVersion(%q) should be true", v)
		}
	}
}

func TestInstallerVersionMustMatchOfferAndBeNewer(t *testing.T) {
	// A reply pairing "99.0.0" with an old, genuinely signed installer.
	if err := checkInstallerVersion("2.0.0", "99.0.0", "3.0.0"); err == nil {
		t.Fatal("an installer whose embedded version differs from the offer must be refused")
	}
	if err := checkInstallerVersion("3.0.0", "3.0.0", "3.0.0"); err == nil {
		t.Fatal("a sideways install must be refused")
	}
	if err := checkInstallerVersion("2.9.0", "2.9.0", "3.0.0"); err == nil {
		t.Fatal("a downgrade must be refused even when offer and installer agree")
	}
	if err := checkInstallerVersion("", "3.0.1", "3.0.0"); err == nil {
		t.Fatal("an installer without a version must be refused")
	}
	if err := checkInstallerVersion(" 3.0.1~beta ", "3.0.1~beta", "3.0.0"); err != nil {
		t.Fatalf("a genuine upgrade must pass: %v", err)
	}
}

func TestSpreadDelayStaysInsideTheWindow(t *testing.T) {
	at := time.Date(2026, 9, 19, 4, 50, 0, 0, time.Local)
	rem := windowRemaining(at, 5)
	if rem != 10*time.Minute {
		t.Fatalf("remaining = %v, want 10m", rem)
	}
	for range 1000 {
		if d := spreadDelay(rem); d < 0 || d >= rem {
			t.Fatalf("delay %v escapes a window with %v left", d, rem)
		}
	}
	// Spanning midnight: 23:00 in a 22-2 window closes in three hours.
	if got := windowRemaining(time.Date(2026, 9, 19, 23, 0, 0, 0, time.Local), 2); got != 3*time.Hour {
		t.Fatalf("midnight-spanning remaining = %v, want 3h", got)
	}
	if spreadDelay(0) != 0 {
		t.Fatal("no time left means no delay")
	}
}

// windowsUpdater is an updater that believes it runs on Windows, with the
// clock at the given time.
func windowsUpdater(at time.Time) *Updater {
	u := New(Config{Enabled: true, CurrentVersion: "1.0.0", WindowStartHour: 1, WindowEndHour: 5},
		slog.New(slog.DiscardHandler))
	u.goos = "windows"
	u.now = func() time.Time { return at }
	return u
}

func TestConcurrentHintsStartOneUpdate(t *testing.T) {
	// One second of window left, so the spread delay is under a second.
	u := windowsUpdater(time.Date(2026, 9, 19, 4, 59, 59, 0, time.Local))
	var calls atomic.Int32
	done := make(chan struct{}, 8)
	u.apply = func(context.Context, Target, []string, *slog.Logger) error {
		calls.Add(1)
		done <- struct{}{}
		return nil
	}
	offer := Offer{Version: "3.0.1", URL: "https://vendor.example/a.exe"}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); u.HandleHint(offer) }()
	}
	wg.Wait()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the update never ran")
	}
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d concurrent hints started %d updates, want 1", 8, n)
	}
}

func TestCloseAbandonsAScheduledUpdate(t *testing.T) {
	u := windowsUpdater(time.Date(2026, 9, 19, 2, 0, 0, 0, time.Local))
	u.apply = func(context.Context, Target, []string, *slog.Logger) error {
		t.Error("a closed updater must not install")
		return nil
	}
	u.HandleHint(Offer{Version: "3.0.1", URL: "https://vendor.example/a.exe"})
	u.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		u.mu.Lock()
		busy := u.inProgress
		u.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the scheduled update did not stop on Close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
