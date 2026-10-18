package k8s

import (
	"testing"
	"time"
)

func mustNext(t *testing.T, expr string, from string) string {
	t.Helper()
	s, err := parseCron(expr)
	if err != nil {
		t.Fatalf("parseCron(%q): %v", expr, err)
	}
	f, err := time.Parse(time.RFC3339, from)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := s.next(f)
	if !ok {
		t.Fatalf("no next run for %q after %s", expr, from)
	}
	return n.UTC().Format(time.RFC3339)
}

func TestNextRun(t *testing.T) {
	cases := []struct{ expr, from, want string }{
		{"0 8 * * *", "2026-09-14T09:00:00Z", "2026-09-15T08:00:00Z"},
		{"0 * * * *", "2026-09-14T09:34:00Z", "2026-09-14T10:00:00Z"},
		{"*/5 * * * *", "2026-09-14T09:34:00Z", "2026-09-14T09:35:00Z"},
		{"0,30 * * * *", "2026-09-14T09:34:00Z", "2026-09-14T10:00:00Z"},
		{"0 18 * * *", "2026-09-14T09:00:00Z", "2026-09-14T18:00:00Z"},
		// Strictly after: a schedule matching `from` exactly must roll forward.
		{"0 8 * * *", "2026-09-14T08:00:00Z", "2026-09-15T08:00:00Z"},
		// Shorthands.
		{"@daily", "2026-09-14T09:00:00Z", "2026-09-15T00:00:00Z"},
		{"@hourly", "2026-09-14T09:34:00Z", "2026-09-14T10:00:00Z"},
		// Ranges and month rollover.
		{"30 2 * * 1-5", "2026-09-12T00:00:00Z", "2026-09-14T02:30:00Z"}, // Sat -> Mon
		{"0 0 1 * *", "2026-09-14T09:00:00Z", "2026-10-01T00:00:00Z"},
		// Leap day: the longest legal gap.
		{"0 0 29 2 *", "2026-03-01T00:00:00Z", "2028-02-29T00:00:00Z"},
	}
	for _, c := range cases {
		if got := mustNext(t, c.expr, c.from); got != c.want {
			t.Errorf("next(%q, %s) = %s, want %s", c.expr, c.from, got, c.want)
		}
	}
}

func TestDayOfMonthAndWeekdayAreUnionedWhenBothRestricted(t *testing.T) {
	// The 1st of the month OR any Monday.
	got := mustNext(t, "0 0 1 * 1", "2026-09-02T00:00:00Z") // Wed 2 Sep
	if want := "2026-09-07T00:00:00Z"; got != want {        // Mon 7 Sep, before the 1st
		t.Fatalf("got %s, want %s (union, not intersection)", got, want)
	}
}

func TestSundayIsBothZeroAndSeven(t *testing.T) {
	a := mustNext(t, "0 0 * * 0", "2026-09-14T00:00:00Z")
	b := mustNext(t, "0 0 * * 7", "2026-09-14T00:00:00Z")
	if a != b {
		t.Fatalf("weekday 0 gave %s but 7 gave %s; both mean Sunday", a, b)
	}
}

func TestRejectsWhatItCannotProject(t *testing.T) {
	for _, bad := range []string{"", "0 8 * *", "@every 5m", "99 * * * *", "0 8 * * abc", "*/0 * * * *"} {
		if _, err := parseCron(bad); err == nil {
			t.Errorf("parseCron(%q) accepted an expression it cannot evaluate", bad)
		}
	}
}

func TestImpossibleScheduleTerminates(t *testing.T) {
	s, err := parseCron("0 0 30 2 *") // 30 February
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	from, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	if _, ok := s.next(from); ok {
		t.Fatal("claimed a next run for 30 February")
	}
}

func TestWeekdaySevenIsSundayInRangesAndSteps(t *testing.T) {
	cases := []struct {
		field string
		want  []int
	}{
		{"7", []int{0}},
		{"1-7", []int{0, 1, 2, 3, 4, 5, 6}},
		{"5-7", []int{0, 5, 6}},
		{"*/7", []int{0}},
		{"0,7", []int{0}},
		{"*", []int{0, 1, 2, 3, 4, 5, 6}},
	}
	for _, c := range cases {
		s, err := parseCron("0 0 * * " + c.field)
		if err != nil {
			t.Errorf("%q: %v", c.field, err)
			continue
		}
		if !equalInts(s.weekdays, c.want) {
			t.Errorf("%q weekdays = %v, want %v", c.field, s.weekdays, c.want)
		}
	}
}

func TestCronAcceptsNames(t *testing.T) {
	s, err := parseCron("0 9 * jan,Mar-MAY MON-FRI")
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(s.months, []int{1, 3, 4, 5}) || !equalInts(s.weekdays, []int{1, 2, 3, 4, 5}) {
		t.Fatalf("months %v weekdays %v", s.months, s.weekdays)
	}
	if got := mustNext(t, "0 9 * * MON-FRI", "2026-09-19T10:00:00Z"); got != "2026-09-21T09:00:00Z" {
		t.Errorf("Saturday → next weekday 09:00 = %s", got)
	}
}

func TestCronStartSlashStep(t *testing.T) {
	s, err := parseCron("5/15 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(s.minutes, []int{5, 20, 35, 50}) {
		t.Fatalf("5/15 minutes = %v, want [5 20 35 50]", s.minutes)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
