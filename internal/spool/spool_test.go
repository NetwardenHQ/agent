//go:build !windows

package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func ev(i int) string {
	return fmt.Sprintf(`{"v":1,"type":"crowdsec.ban_spike","severity":"warning","title":"t%d","detail":"d","occurred_at":"2026-10-18T13:00:00Z","dedupe_key":"k%d","labels":{"a":"b"}}`, i, i)
}

// newSpool builds a trusted spool owned by the current user.
func newSpool(t *testing.T) (string, *Reader, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "events"), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	r := New(dir, WithOwnerUID(os.Getuid()), WithClock(func() time.Time { return now }))
	return dir, r, &now
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func eventsOf(t *testing.T, b Batch) []Event {
	t.Helper()
	for _, s := range b.Snapshots {
		if s.Type == metrics.SnapshotEvents {
			return s.Payload["events"].([]Event)
		}
	}
	return nil
}

func TestParseEvent(t *testing.T) {
	good := ev(1)
	if _, err := ParseEvent([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"v":        strings.Replace(good, `"v":1`, `"v":2`, 1),
		"type":     strings.Replace(good, "crowdsec.ban_spike", "NoDots", 1),
		"severity": strings.Replace(good, "warning", "fatal", 1),
		"time":     strings.Replace(good, "2026-10-18T13:00:00Z", "yesterday", 1),
		"dedupe":   strings.Replace(good, `"dedupe_key":"k1"`, `"dedupe_key":""`, 1),
		"longkey":  strings.Replace(good, `"k1"`, `"`+strings.Repeat("x", 201)+`"`, 1),
		"title":    strings.Replace(good, `"title":"t1"`, `"title":"`+strings.Repeat("x", 201)+`"`, 1),
		"detail":   strings.Replace(good, `"detail":"d"`, `"detail":"`+strings.Repeat("x", 4001)+`"`, 1),
		"labelval": strings.Replace(good, `"a":"b"`, `"a":5`, 1),
		"junk":     "{not json",
	}
	var many []string
	for i := 0; i < 33; i++ {
		many = append(many, fmt.Sprintf(`"l%d":"v"`, i))
	}
	bad["labels33"] = strings.Replace(good, `"a":"b"`, strings.Join(many, ","), 1)
	for name, line := range bad {
		if _, err := ParseEvent([]byte(line)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// 32 labels is the limit and still valid.
	ok := strings.Replace(good, `"a":"b"`, strings.Join(many[:32], ","), 1)
	if _, err := ParseEvent([]byte(ok)); err != nil {
		t.Errorf("32 labels must pass: %v", err)
	}
}

func TestPermissionChecks(t *testing.T) {
	// Wrong owner.
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "events"), 0o700)
	write(t, filepath.Join(dir, "events", "a.jsonl"), ev(1)+"\n")
	r := New(dir, WithOwnerUID(os.Getuid()+1))
	if got := eventsOf(t, r.Next(16, 1<<20)); got != nil {
		t.Fatal("must refuse a directory with the wrong owner")
	}

	// Group/world writable directory.
	dir2, r2, _ := newSpool(t)
	write(t, filepath.Join(dir2, "events", "a.jsonl"), ev(1)+"\n")
	if got := eventsOf(t, r2.Next(16, 1<<20)); len(got) != 1 {
		t.Fatal("control: trusted spool must be read")
	}
	os.Chmod(dir2, 0o770)
	if got := eventsOf(t, r2.Next(16, 1<<20)); got != nil {
		t.Fatal("must refuse a group-writable spool dir")
	}
	os.Chmod(dir2, 0o700)
	os.Chmod(filepath.Join(dir2, "events"), 0o702)
	if got := eventsOf(t, r2.Next(16, 1<<20)); got != nil {
		t.Fatal("must refuse a world-writable events dir")
	}
	os.Chmod(filepath.Join(dir2, "events"), 0o700)

	// World-writable file.
	os.Chmod(filepath.Join(dir2, "events", "a.jsonl"), 0o666)
	if got := eventsOf(t, r2.Next(16, 1<<20)); got != nil {
		t.Fatal("must refuse a world-writable file")
	}
}

func TestSymlinksAndTmpIgnored(t *testing.T) {
	dir, r, _ := newSpool(t)
	outside := filepath.Join(t.TempDir(), "x.jsonl")
	write(t, outside, ev(9)+"\n")
	if err := os.Symlink(outside, filepath.Join(dir, "events", "link.jsonl")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "events", "partial.jsonl.tmp"), ev(8)+"\n")
	if got := eventsOf(t, r.Next(16, 1<<20)); got != nil {
		t.Fatalf("symlink and .tmp must be ignored, got %v", got)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("symlink target must be untouched")
	}

	// Symlinked events directory.
	dir2, r2, _ := newSpool(t)
	os.RemoveAll(filepath.Join(dir2, "events"))
	real := t.TempDir()
	os.Chmod(real, 0o700)
	write(t, filepath.Join(real, "a.jsonl"), ev(1)+"\n")
	os.Symlink(real, filepath.Join(dir2, "events"))
	if got := eventsOf(t, r2.Next(16, 1<<20)); got != nil {
		t.Fatal("symlinked events dir must be refused")
	}
}

func TestDeleteOnlyAfterAck(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "events", "a.jsonl")
	write(t, p, ev(1)+"\nnot json\n\n"+ev(2)+"\n")

	b := r.Next(16, 1<<20)
	if got := eventsOf(t, b); len(got) != 2 {
		t.Fatalf("want 2 valid events, got %d", len(got))
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("file must survive until acked")
	}
	// Failed post: nothing acked; the same events are offered again.
	if got := eventsOf(t, r.Next(16, 1<<20)); len(got) != 2 {
		t.Fatal("unacked events must be re-offered")
	}
	b = r.Next(16, 1<<20)
	b.Ack()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file must be deleted after ack")
	}
	if r.Skipped() == 0 {
		t.Fatal("invalid line must be counted")
	}
	if got := eventsOf(t, r.Next(16, 1<<20)); got != nil {
		t.Fatal("nothing left to send")
	}
}

func TestPartialFileOffsets(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "events", "big.jsonl")
	var sb strings.Builder
	for i := 0; i < 1100; i++ {
		sb.WriteString(ev(i) + "\n")
	}
	write(t, p, sb.String())
	write(t, filepath.Join(dir, "events", "z.jsonl"), ev(5000)+"\n")

	want := []int{500, 500, 101}
	for n, w := range want {
		b := r.Next(16, 1<<30)
		got := eventsOf(t, b)
		if len(got) != w {
			t.Fatalf("post %d: want %d events, got %d", n, w, len(got))
		}
		if n == 0 && got[0].DedupeKey != "k0" || n == 1 && got[0].DedupeKey != "k500" {
			t.Fatalf("post %d starts at %s", n, got[0].DedupeKey)
		}
		if n < 2 {
			if _, err := os.Stat(p); err != nil {
				t.Fatal("partially delivered file must stay")
			}
		}
		b.Ack()
	}
	for _, f := range []string{"big.jsonl", "z.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, "events", f)); !os.IsNotExist(err) {
			t.Fatalf("%s must be gone", f)
		}
	}
}

func TestExactly500EventsFileCompletes(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "events", "a.jsonl")
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString(ev(i) + "\n")
	}
	write(t, p, sb.String())
	b := r.Next(16, 1<<30)
	b.Ack()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("a file with exactly 500 events is fully carried and must be deleted")
	}
}

func TestByteBudgetDefersEvents(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "events", "a.jsonl")
	write(t, p, ev(1)+"\n"+ev(2)+"\n"+ev(3)+"\n")
	one, _ := json.Marshal(Event{V: 1, Type: "crowdsec.ban_spike", Severity: "warning", Title: "t1", Detail: "d", OccurredAt: "2026-10-18T13:00:00Z", DedupeKey: "k1", Labels: map[string]string{"a": "b"}})
	budget := snapshotOverhead + len(`{"events":[]}`) + 2*(len(one)+1) + 5
	b := r.Next(16, budget)
	if got := eventsOf(t, b); len(got) != 2 {
		t.Fatalf("budget allows 2 events, got %d", len(got))
	}
	b.Ack()
	if _, err := os.Stat(p); err != nil {
		t.Fatal("file with a deferred line must stay")
	}
	b = r.Next(16, budget)
	if got := eventsOf(t, b); len(got) != 1 || got[0].DedupeKey != "k3" {
		t.Fatalf("remaining event must follow, got %+v", got)
	}
	if got := eventsOf(t, r.Next(16, 10)); got != nil {
		t.Fatal("no events when no budget")
	}
}

func TestOversizedLineAndFile(t *testing.T) {
	dir, r, _ := newSpool(t)
	huge := `{"v":1,"detail":"` + strings.Repeat("x", 40*1024) + `"}`
	write(t, filepath.Join(dir, "events", "a.jsonl"), huge+"\n"+ev(1)+"\n")
	b := r.Next(16, 1<<30)
	if got := eventsOf(t, b); len(got) != 1 || got[0].DedupeKey != "k1" {
		t.Fatalf("oversized line skipped, next kept: %+v", got)
	}

	write(t, filepath.Join(dir, "events", "b.jsonl"), strings.Repeat("a", MaxEventFileBytes+1))
	r2 := New(dir, WithOwnerUID(os.Getuid()))
	b2 := r2.Next(16, 1<<30)
	for _, e := range eventsOf(t, b2) {
		if e.DedupeKey == "" {
			t.Fatal("unexpected")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "events", "b.jsonl")); err != nil {
		t.Fatal("an oversized file is left alone, not deleted")
	}
}

func TestExposureHashAndHourlyResend(t *testing.T) {
	dir, r, now := newSpool(t)
	p := filepath.Join(dir, "exposure.json")
	write(t, p, `{"v":1,"analyzer":"pfeval","wan":[]}`)

	send := func() (metrics.Snapshot, bool) {
		b := r.Next(16, 1<<20)
		for _, s := range b.Snapshots {
			if s.Type == metrics.SnapshotNetworkExposure {
				b.Ack()
				return s, true
			}
		}
		return metrics.Snapshot{}, false
	}

	s, ok := send()
	if !ok || s.Payload["analyzer"] != "pfeval" {
		t.Fatalf("first send missing: %v", s)
	}
	if _, ok := send(); ok {
		t.Fatal("unchanged exposure must not be resent within the hour")
	}
	*now = now.Add(59 * time.Minute)
	if _, ok := send(); ok {
		t.Fatal("still inside the hour")
	}
	*now = now.Add(2 * time.Minute)
	if _, ok := send(); !ok {
		t.Fatal("must resend after an hour")
	}
	if _, ok := send(); ok {
		t.Fatal("resend resets the clock")
	}
	write(t, p, `{"v":1,"analyzer":"pfeval","wan":[{"interface":"em0"}]}`)
	if _, ok := send(); !ok {
		t.Fatal("changed exposure must be sent at once")
	}

	// Without an ack nothing is recorded.
	write(t, p, `{"v":1,"x":1}`)
	r.Next(16, 1<<20)
	if _, ok := send(); !ok {
		t.Fatal("unacked exposure must be offered again")
	}
}

func TestExposureLimitsAndPriority(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "exposure.json")
	write(t, p, `{"pad":"`+strings.Repeat("x", MaxExposureBytes)+`"}`)
	if b := r.Next(16, 1<<30); len(b.Snapshots) != 0 {
		t.Fatal("exposure over 256 KB must be rejected")
	}
	write(t, p, `[1,2]`)
	if b := r.Next(16, 1<<30); len(b.Snapshots) != 0 {
		t.Fatal("non-object exposure must be rejected")
	}

	write(t, p, `{"v":1}`)
	write(t, filepath.Join(dir, "events", "a.jsonl"), ev(1)+"\n")
	b := r.Next(1, 1<<20)
	if len(b.Snapshots) != 1 || b.Snapshots[0].Type != metrics.SnapshotNetworkExposure {
		t.Fatal("with one slot, exposure wins and events are deferred")
	}
	b = r.Next(2, 1<<20)
	if len(b.Snapshots) != 2 {
		t.Fatal("two slots carry both")
	}
	if b := r.Next(0, 1<<20); len(b.Snapshots) != 0 {
		t.Fatal("no slots, no snapshots")
	}
}

func TestIdentityAllowedKeys(t *testing.T) {
	dir, r, _ := newSpool(t)
	write(t, filepath.Join(dir, "identity.json"), `{"unisense_version":"1.4.2","api_key":"secret","role":"server"}`)
	got := r.Identity()
	if len(got) != 1 || got["unisense_version"] != "1.4.2" {
		t.Fatalf("only allowed keys: %v", got)
	}
	write(t, filepath.Join(dir, "identity.json"), `{"nothing":1}`)
	if r.Identity() != nil {
		t.Fatal("no allowed key means nil")
	}
	var nilReader *Reader
	if nilReader.Identity() != nil || len(nilReader.Next(16, 100).Snapshots) != 0 {
		t.Fatal("nil reader is inert")
	}
	nilReader.Next(1, 1).Ack()
}

func TestEnsureDirs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var", "spool")
	r := New(dir, WithOwnerUID(os.Getuid()))
	if err := r.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, filepath.Join(dir, "events")} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, fi, err)
		}
	}
	// Existing directories are left alone.
	os.Chmod(dir, 0o750)
	if err := r.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o750 {
		t.Fatal("existing directory must not be modified")
	}
	if err := New("").EnsureDirs(); err != nil {
		t.Fatal(err)
	}
}

func TestSentTotalAndPending(t *testing.T) {
	dir, r, _ := newSpool(t)
	write(t, filepath.Join(dir, "events", "a.jsonl"), ev(1)+"\n\n"+ev(2)+"\n"+ev(3))
	if got := r.Pending(); got != 3 {
		t.Fatalf("pending %d", got)
	}
	b := r.Next(16, 1<<20)
	if r.SentTotal() != 0 {
		t.Fatal("nothing sent before ack")
	}
	b.Ack()
	if r.SentTotal() != 3 || r.Pending() != 0 {
		t.Fatalf("sent=%d pending=%d", r.SentTotal(), r.Pending())
	}
	var nilR *Reader
	if nilR.SentTotal() != 0 || nilR.Pending() != 0 {
		t.Fatal("nil reader")
	}
}

func TestSkippedCountsEachInvalidLineOnce(t *testing.T) {
	dir, r, _ := newSpool(t)
	write(t, filepath.Join(dir, "events", "a.jsonl"), "{bad\n"+ev(1)+"\n")
	r.Next(16, 1<<20) // not acknowledged
	r.Next(16, 1<<20)
	if got := r.Skipped(); got != 1 {
		t.Fatalf("one invalid line counted %d times", got)
	}
}

func TestStateOfVanishedFilesIsForgotten(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "events", "a.jsonl")
	var sb strings.Builder
	for i := 0; i < 600; i++ {
		sb.WriteString(ev(i) + "\n")
	}
	write(t, p, sb.String())
	r.Next(16, 1<<30).Ack() // 500 delivered, offset remembered
	if len(r.offsets) != 1 {
		t.Fatal("control: a partially delivered file has an offset")
	}
	os.Remove(p) // the producer withdrew it
	r.Next(16, 1<<30)
	if len(r.offsets) != 0 || len(r.skipCounted) != 0 {
		t.Fatalf("state kept for a vanished file: offsets=%v", r.offsets)
	}
}

func TestEventThatNeverFitsIsSkippedNotStalledForever(t *testing.T) {
	dir, r, _ := newSpool(t)
	big := fmt.Sprintf(`{"v":1,"type":"a.b","severity":"info","title":"t","detail":"%s","occurred_at":"2026-10-18T13:00:00Z","dedupe_key":"big"}`, strings.Repeat("x", 3000))
	write(t, filepath.Join(dir, "events", "a.jsonl"), big+"\n"+ev(1)+"\n")
	budget := 2000 // room for ev(1), never for the big one

	for i := 1; i < maxStalledCycles; i++ {
		if got := eventsOf(t, r.Next(16, budget)); got != nil {
			t.Fatalf("cycle %d: the head event is deferred, not overtaken: %v", i, got)
		}
	}
	got := eventsOf(t, r.Next(16, budget))
	if len(got) != 1 || got[0].DedupeKey != "k1" {
		t.Fatalf("after %d posts the oversized event must be skipped and the queue move on, got %v", maxStalledCycles, got)
	}
	if r.Skipped() != 1 {
		t.Fatalf("the skipped event must be counted, got %d", r.Skipped())
	}
}

func TestPendingFollowsChanges(t *testing.T) {
	dir, r, _ := newSpool(t)
	p := filepath.Join(dir, "events", "a.jsonl")
	write(t, p, ev(1)+"\n")
	if got := r.Pending(); got != 1 {
		t.Fatalf("pending %d", got)
	}
	if got := r.Pending(); got != 1 {
		t.Fatalf("cached pending %d", got)
	}
	write(t, p, ev(1)+"\n"+ev(2)+"\n"+strings.Repeat("y", maxLineBytes+10)+"\n")
	if got := r.Pending(); got != 3 {
		t.Fatalf("pending after the file grew: %d, want 3 (an over-long line counts)", got)
	}
}

func TestUntrustedParentIsRefused(t *testing.T) {
	// Whoever can write a parent can swap the spool for their own.
	parent := t.TempDir()
	os.Chmod(parent, 0o700)
	dir := filepath.Join(parent, "spool")
	os.Mkdir(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "events"), 0o700)
	write(t, filepath.Join(dir, "events", "a.jsonl"), ev(1)+"\n")
	r := New(dir, WithOwnerUID(os.Getuid()))
	if got := eventsOf(t, r.Next(16, 1<<20)); len(got) != 1 {
		t.Fatal("control: a trusted chain is read")
	}
	os.Chmod(parent, 0o777)
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	if got := eventsOf(t, r.Next(16, 1<<20)); got != nil {
		t.Fatal("a world-writable parent must make the spool untrusted")
	}
}
