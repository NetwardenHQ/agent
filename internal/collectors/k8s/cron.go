package k8s

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

/*
A minimal cron expression evaluator, enough for Kubernetes CronJob schedules.

The agent talks to the API server over plain HTTPS without client-go, and a
dependency to answer "when does this run next" would be out of proportion. The
grammar Kubernetes accepts is the standard five-field form plus the
@shorthands.

Everything is evaluated in UTC unless the CronJob names a timezone, which is
what the API server itself does.
*/

type cronSchedule struct {
	minutes  []int
	hours    []int
	days     []int // day of month, 1-31
	months   []int // 1-12
	weekdays []int // 0-6, Sunday = 0
	// A schedule that restricts both day-of-month and day-of-week matches when
	// either matches, as in standard cron.
	domRestricted bool
	dowRestricted bool
}

var cronShorthands = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

func parseCron(expr string) (*cronSchedule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty schedule")
	}
	// @every has no fixed wall-clock times and cannot be projected without
	// knowing the last run.
	if strings.HasPrefix(expr, "@every") {
		return nil, fmt.Errorf("unsupported schedule %q", expr)
	}
	if sub, ok := cronShorthands[strings.ToLower(expr)]; ok {
		expr = sub
	}

	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("expected 5 fields, got %d", len(fields))
	}

	s := &cronSchedule{}
	var err error
	if s.minutes, err = cronField(fields[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if s.hours, err = cronField(fields[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if s.days, err = cronField(fields[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("day of month: %w", err)
	}
	if s.months, err = cronField(fields[3], 1, 12, cronMonthNames); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	// Day of week is expanded over 0-7 (7 is also Sunday) and 7 is then folded
	// onto 0. Folding the text instead would turn "1-7" into the invalid "1-0".
	if s.weekdays, err = cronField(fields[4], 0, 7, cronDayNames); err != nil {
		return nil, fmt.Errorf("day of week: %w", err)
	}
	s.weekdays = foldSunday(s.weekdays)
	s.domRestricted = fields[2] != "*" && fields[2] != "?"
	s.dowRestricted = fields[4] != "*" && fields[4] != "?"
	return s, nil
}

// Names accepted in place of numbers, case-insensitively, as Kubernetes does.
var (
	cronMonthNames = map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}
	cronDayNames = map[string]int{
		"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
	}
)

// foldSunday maps weekday 7 onto 0, keeping the list sorted and unique.
func foldSunday(days []int) []int {
	if len(days) == 0 || days[len(days)-1] != 7 {
		return days
	}
	days = days[:len(days)-1]
	if len(days) > 0 && days[0] == 0 {
		return days
	}
	return append([]int{0}, days...)
}

// cronValue reads one number, or one of the field's names.
func cronValue(s string, names map[string]int) (int, error) {
	if n, ok := names[strings.ToLower(s)]; ok {
		return n, nil
	}
	return strconv.Atoi(s)
}

// cronField expands one field into the concrete values it matches.
func cronField(f string, min, max int, names map[string]int) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(f, ",") {
		step := 1
		stepped := false
		if i := strings.Index(part, "/"); i >= 0 {
			var err error
			if step, err = strconv.Atoi(part[i+1:]); err != nil || step <= 0 {
				return nil, fmt.Errorf("bad step in %q", part)
			}
			part = part[:i]
			stepped = true
		}

		lo, hi := min, max
		switch {
		case part == "*" || part == "?" || part == "":
			// full range
		case strings.Contains(part, "-"):
			bits := strings.SplitN(part, "-", 2)
			var err error
			if lo, err = cronValue(bits[0], names); err != nil {
				return nil, fmt.Errorf("bad range %q", part)
			}
			if hi, err = cronValue(bits[1], names); err != nil {
				return nil, fmt.Errorf("bad range %q", part)
			}
		default:
			n, err := cronValue(part, names)
			if err != nil {
				return nil, fmt.Errorf("bad value %q", part)
			}
			lo, hi = n, n
			// "N/step" means from N to the end of the range, every step.
			if stepped {
				hi = max
			}
		}
		if lo < min || hi > max || lo > hi {
			return nil, fmt.Errorf("%q out of range %d-%d", part, min, max)
		}
		for v := lo; v <= hi; v += step {
			seen[v] = true
		}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	// Sorted so matching can stop early and so tests are deterministic.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// next returns the first time strictly after `from` that the schedule matches.
//
// The search is bounded to four years: the longest gap a valid expression can
// produce is Feb 29, and an unsatisfiable one (Feb 30) must terminate.
func (s *cronSchedule) next(from time.Time) (time.Time, bool) {
	t := from.Truncate(time.Minute).Add(time.Minute)
	limit := from.AddDate(4, 0, 0)
	for t.Before(limit) {
		if !contains(s.months, int(t.Month())) {
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location()).AddDate(0, 1, 0)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		if !contains(s.hours, t.Hour()) {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
			continue
		}
		if contains(s.minutes, t.Minute()) {
			return t, true
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, false
}

// dayMatches implements cron's day-of-month/day-of-week rule: when both are
// restricted, the day matches if either does.
func (s *cronSchedule) dayMatches(t time.Time) bool {
	dom := contains(s.days, t.Day())
	dow := contains(s.weekdays, int(t.Weekday()))
	switch {
	case s.domRestricted && s.dowRestricted:
		return dom || dow
	case s.domRestricted:
		return dom
	case s.dowRestricted:
		return dow
	default:
		return true
	}
}
