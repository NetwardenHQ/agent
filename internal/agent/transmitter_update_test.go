package agent

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/NetwardenHQ/agent/internal/selfupdate"
)

// newHintTransmitter returns a transmitter wired to capture update hints.
func newHintTransmitter() (*HTTPTransmitter, *[]selfupdate.Offer) {
	seen := &[]selfupdate.Offer{}
	t := &HTTPTransmitter{logger: slog.New(slog.DiscardHandler)}
	t.SetUpdateHintHandler(func(o selfupdate.Offer) { *seen = append(*seen, o) })
	return t, seen
}

func TestHandleResponseSurfacesUpdateHint(t *testing.T) {
	tr, seen := newHintTransmitter()
	tr.handleResponse(strings.NewReader(
		`{"success":true,"data":{"accepted":true,"agent_update":` +
			`{"version":"3.0.1","url":"https://mirror.test/a.exe","sha256":"abc"}}}`))

	if len(*seen) != 1 {
		t.Fatalf("expected one hint, got %v", *seen)
	}
	got := (*seen)[0]
	if got.Version != "3.0.1" || got.URL != "https://mirror.test/a.exe" || got.SHA256 != "abc" {
		t.Fatalf("offer not carried through: %+v", got)
	}
}

func TestHandleResponseIgnoresOrdinaryReply(t *testing.T) {
	// The ordinary ack an up-to-date agent receives.
	tr, seen := newHintTransmitter()
	tr.handleResponse(strings.NewReader(
		`{"success":true,"data":{"accepted":true,"metrics":{"accepted":12,"failed":0}}}`))

	if len(*seen) != 0 {
		t.Fatalf("expected no hint, got %v", *seen)
	}
}

func TestHandleResponseToleratesGarbage(t *testing.T) {
	// An unparseable reply must not turn a successful send into an error or a
	// panic: the metrics were already accepted.
	cases := []string{
		"",
		"not json at all",
		"{",
		`{"data":null}`,
		`{"data":{"agent_update":null}}`,
		`{"data":{"agent_update":{}}}`,
		`{"data":{"agent_update":{"version":""}}}`,
		`[1,2,3]`,
	}
	for _, body := range cases {
		tr, seen := newHintTransmitter()
		tr.handleResponse(strings.NewReader(body))
		if len(*seen) != 0 {
			t.Fatalf("body %q should produce no hint, got %v", body, *seen)
		}
	}
}

func TestHandleResponseIsBounded(t *testing.T) {
	// 4 MB of junk against the 64 KB read limit.
	tr, seen := newHintTransmitter()
	tr.handleResponse(strings.NewReader(strings.Repeat("A", 4*1024*1024)))
	if len(*seen) != 0 {
		t.Fatalf("expected no hint from junk, got %v", *seen)
	}
}

func TestHandleResponseWithoutHandlerDoesNotPanic(t *testing.T) {
	tr := &HTTPTransmitter{logger: slog.New(slog.DiscardHandler)}
	tr.handleResponse(strings.NewReader(`{"data":{"agent_update":{"version":"9.9.9"}}}`))
}
