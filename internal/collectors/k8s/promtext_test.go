package k8s

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestParsePromTextPicksOnlyWantedSeries(t *testing.T) {
	body := `# HELP cnpg_collector_up whether the collector is up
# TYPE cnpg_collector_up gauge
cnpg_collector_up{cluster="postgres"} 1
cnpg_pg_database_size_bytes{datname="appdb"} 1.234e+09
cnpg_pg_database_size_bytes{datname="analytics"} 5000
something_else_entirely{a="b"} 99
`
	got := parseProm(body, map[string]bool{
		"cnpg_collector_up":           true,
		"cnpg_pg_database_size_bytes": true,
	})
	if len(got) != 3 {
		t.Fatalf("got %d samples, want 3 (the unwanted series must be skipped)", len(got))
	}
	for _, s := range got {
		if s.Name == "something_else_entirely" {
			t.Fatal("returned a series that was not asked for")
		}
	}
	if got[1].Labels["datname"] != "appdb" || !almost(got[1].Value, 1.234e9) {
		t.Errorf("bad sample: %+v", got[1])
	}
}

func TestParsePromTextHandlesSpacesInLabelValues(t *testing.T) {
	body := `cnpg_backends{application_name="TimescaleDB Background Worker Scheduler",datname="appdb"} 3`
	got := parseProm(body, map[string]bool{"cnpg_backends": true})
	if len(got) != 1 {
		t.Fatalf("got %d samples, want 1", len(got))
	}
	if got[0].Labels["application_name"] != "TimescaleDB Background Worker Scheduler" {
		t.Errorf("application_name = %q", got[0].Labels["application_name"])
	}
	if !almost(got[0].Value, 3) {
		t.Errorf("value = %v", got[0].Value)
	}
}

func TestParsePromTextSkipsCommentsAndBadValues(t *testing.T) {
	body := `# a comment
cnpg_x{a="1"} NaN
cnpg_x{a="2"} notanumber
cnpg_x{a="3"} 7
`
	got := parseProm(body, map[string]bool{"cnpg_x": true})
	// ParseFloat accepts NaN, so only the non-numeric value is asserted
	// absent.
	for _, s := range got {
		if s.Labels["a"] == "2" {
			t.Fatal("accepted a non-numeric value")
		}
	}
	found := false
	for _, s := range got {
		if s.Labels["a"] == "3" && almost(s.Value, 7) {
			found = true
		}
	}
	if !found {
		t.Fatal("did not read the one good sample")
	}
}

func TestParsePromTextHandlesEscapedQuotes(t *testing.T) {
	body := `cnpg_x{msg="he said \"hi\"",b="2"} 1`
	got := parseProm(body, map[string]bool{"cnpg_x": true})
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Labels["msg"] != `he said "hi"` || got[0].Labels["b"] != "2" {
		t.Errorf("labels = %+v", got[0].Labels)
	}
}

func TestParsePromTextHandlesUnlabelledSeries(t *testing.T) {
	got := parseProm("cnpg_x 42\n", map[string]bool{"cnpg_x": true})
	if len(got) != 1 || !almost(got[0].Value, 42) {
		t.Fatalf("got %+v", got)
	}
}

// parseProm parses an in-memory page. A strings.Reader cannot fail, so it
// panics on error.
func parseProm(body string, want map[string]bool) []promSample {
	got, err := parsePromText(strings.NewReader(body), want)
	if err != nil {
		panic(err)
	}
	return got
}

// A sample may carry a trailing timestamp in milliseconds.
func TestParsePromTextIgnoresTrailingTimestamp(t *testing.T) {
	body := "cnpg_x{a=\"1\"} 42 1726000000000\ncnpg_x 7 1726000000000\n"
	got := parseProm(body, map[string]bool{"cnpg_x": true})
	if len(got) != 2 {
		t.Fatalf("got %d samples, want 2: %+v", len(got), got)
	}
	if got[0].Value != 42 || got[0].Labels["a"] != "1" || got[1].Value != 7 {
		t.Fatalf("timestamp mistaken for the value: %+v", got)
	}
}

func TestParsePromTextHandlesBracesInLabelValues(t *testing.T) {
	got := parseProm(`cnpg_x{q="a} b",r="c"} 5`+"\n", map[string]bool{"cnpg_x": true})
	if len(got) != 1 || got[0].Value != 5 || got[0].Labels["q"] != "a} b" || got[0].Labels["r"] != "c" {
		t.Fatalf("got %+v", got)
	}
}

// A read error, including an over-long line, fails the whole page.
func TestParsePromTextReportsReadErrors(t *testing.T) {
	r := io.MultiReader(strings.NewReader("cnpg_x 1\n"), iotest.ErrReader(errors.New("connection reset")))
	if got, err := parsePromText(r, map[string]bool{"cnpg_x": true}); err == nil {
		t.Fatalf("expected the read error, got samples %+v", got)
	}
	long := "cnpg_x{a=\"" + strings.Repeat("x", 2<<20) + "\"} 1\n"
	if _, err := parsePromText(strings.NewReader(long), map[string]bool{"cnpg_x": true}); err == nil {
		t.Fatal("a line beyond the scanner buffer must be an error, not a silent stop")
	}
}
