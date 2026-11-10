package agent

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// reportServer stands in for the platform's report endpoint and records how
// each post arrived.
type reportServer struct {
	mu        sync.Mutex
	encodings []string
	bodies    []string
	// refuseGzip answers 415 to a compressed post, like a platform (or a
	// proxy in front of it) that does not read them.
	refuseGzip bool
	reply      string
	status     int
}

func (s *reportServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	encoding := r.Header.Get("Content-Encoding")
	s.encodings = append(s.encodings, encoding)
	var body []byte
	if encoding == "gzip" {
		if s.refuseGzip {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ = io.ReadAll(zr)
	} else {
		body, _ = io.ReadAll(r.Body)
	}
	s.bodies = append(s.bodies, string(body))
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	_, _ = io.WriteString(w, s.reply)
}

func newTransportTransmitter(t *testing.T, s *reportServer) *HTTPTransmitter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)
	tr := &HTTPTransmitter{
		config:     &config.Config{TenantID: "abcdefghij", ServerURL: srv.URL, APIKey: "nw_sk_test"},
		logger:     testLogger(),
		version:    "3.5.0",
		hostname:   "test-host",
		httpClient: srv.Client(),
	}
	tr.lastLatencyMs.Store(-1)
	return tr
}

// bigBatch is a batch large enough to be worth compressing.
func bigBatch() []metrics.Metric {
	out := make([]metrics.Metric, 60)
	for i := range out {
		out[i] = metrics.Metric{Name: "network_bytes_recv_total", Value: float64(i), Timestamp: time.Now(),
			Labels: map[string]string{"interface": "eth0", "host": "test-host"}}
	}
	return out
}

func TestReportsAreCompressedOnceTheServerSaysItReadsThem(t *testing.T) {
	s := &reportServer{reply: `{"success":true,"data":{"accepted":true,"accepts_gzip":true}}`}
	tr := newTransportTransmitter(t, s)

	for i := 0; i < 2; i++ {
		if err := tr.Send(context.Background(), bigBatch(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.encodings) != 2 || s.encodings[0] != "" || s.encodings[1] != "gzip" {
		t.Fatalf("encodings %q, want the first plain and the second gzip", s.encodings)
	}
	// What the server inflates is the same report.
	if s.bodies[1] == "" || !strings.Contains(s.bodies[1], `"metric_name":"network_bytes_recv_total"`) || !strings.Contains(s.bodies[1], `"hostname":"test-host"`) {
		t.Fatalf("compressed body did not inflate to a report: %.120s", s.bodies[1])
	}
}

func TestAServerThatNeverSaysSoIsNeverSentACompressedReport(t *testing.T) {
	s := &reportServer{reply: `{"success":true,"data":{"accepted":true}}`}
	tr := newTransportTransmitter(t, s)
	for i := 0; i < 3; i++ {
		_ = tr.Send(context.Background(), bigBatch(), nil)
	}
	for _, e := range s.encodings {
		if e != "" {
			t.Fatalf("compressed without being told to: %q", s.encodings)
		}
	}
}

// Something on the way may not pass a compressed body through even though
// the platform reads them. The report must still arrive, in the same Send.
func TestACompressedReportThatIsRefusedIsSentPlainAndCompressionStaysOff(t *testing.T) {
	s := &reportServer{refuseGzip: true, reply: `{"success":true,"data":{"accepted":true,"accepts_gzip":true}}`}
	tr := newTransportTransmitter(t, s)
	tr.AllowGzip()

	if err := tr.Send(context.Background(), bigBatch(), nil); err != nil {
		t.Fatalf("the report did not get through: %v", err)
	}
	if len(s.encodings) != 2 || s.encodings[0] != "gzip" || s.encodings[1] != "" {
		t.Fatalf("encodings %q, want gzip then plain", s.encodings)
	}
	// The reply to the plain post says gzip is fine again; the refusal stands.
	if err := tr.Send(context.Background(), bigBatch(), nil); err != nil {
		t.Fatal(err)
	}
	if got := s.encodings[len(s.encodings)-1]; got != "" || len(s.encodings) != 3 {
		t.Fatalf("compression was tried again after a refusal: %q", s.encodings)
	}
}

func TestSmallReportsAreNotCompressed(t *testing.T) {
	s := &reportServer{reply: `{"success":true,"data":{"accepted":true,"accepts_gzip":true}}`}
	tr := newTransportTransmitter(t, s)
	tr.AllowGzip()
	one := []metrics.Metric{{Name: "cpu_usage_percent", Value: 1, Timestamp: time.Now()}}
	if err := tr.Send(context.Background(), one, nil); err != nil {
		t.Fatal(err)
	}
	if s.encodings[0] != "" {
		t.Fatalf("a %d-byte report was compressed", len(s.bodies[0]))
	}
}

func TestARefusedReportIsMarkedAsRejected(t *testing.T) {
	s := &reportServer{status: http.StatusBadRequest}
	tr := newTransportTransmitter(t, s)
	err := tr.Send(context.Background(), bigBatch(), nil)
	if !errors.Is(err, errPayloadRejected) {
		t.Fatalf("a 400 was not marked as a rejected payload: %v", err)
	}
	if len(s.encodings) != 1 {
		t.Fatalf("a rejected payload was sent %d times", len(s.encodings))
	}
}

func TestReplyCarriesTheSettingsRevision(t *testing.T) {
	tr := &HTTPTransmitter{logger: testLogger()}
	if tr.ConfigRev() != "" {
		t.Fatal("a revision before any reply")
	}
	tr.handleResponse(strings.NewReader(`{"success":true,"data":{"accepted":true,"config_rev":"0123456789abcdef"}}`))
	if got := tr.ConfigRev(); got != "0123456789abcdef" {
		t.Fatalf("revision %q", got)
	}
	// A reply without one (an older platform) changes nothing.
	tr.handleResponse(strings.NewReader(`{"success":true,"data":{"accepted":true}}`))
	if got := tr.ConfigRev(); got != "0123456789abcdef" {
		t.Fatalf("revision lost: %q", got)
	}
}

// revTransmitter is a transmitter that only reports a settings revision.
type revTransmitter struct{ rev string }

func (t *revTransmitter) Send(context.Context, []metrics.Metric, []metrics.Snapshot) error {
	return nil
}
func (t *revTransmitter) Close() error      { return nil }
func (t *revTransmitter) ConfigRev() string { return t.rev }

func TestAChangedRevisionAsksForTheConfig(t *testing.T) {
	tr := &revTransmitter{}
	a := &Agent{logger: testLogger(), transmitter: tr, configFetched: true}
	now := time.Now()
	a.lastConfigFetch = now.Add(-time.Hour)

	if a.configChanged(now) {
		t.Fatal("no revision yet")
	}
	tr.rev = "aaaa"
	if a.configChanged(now) {
		t.Fatal("the first revision seen is the config fetched at startup")
	}
	if a.configChanged(now) {
		t.Fatal("an unchanged revision asked for the config")
	}
	tr.rev = "bbbb"
	if !a.configChanged(now) {
		t.Fatal("a changed revision did not ask for the config")
	}
	if a.configChanged(now) {
		t.Fatal("asked twice for one change")
	}
}

func TestRevisionHandlingWhenTheStartupFetchFailed(t *testing.T) {
	tr := &revTransmitter{rev: "aaaa"}
	a := &Agent{logger: testLogger(), transmitter: tr} // configFetched is false
	now := time.Now()

	// Straight after the failed attempt: not yet, the server was just asked.
	a.lastConfigFetch = now.Add(-5 * time.Second)
	if a.configChanged(now) {
		t.Fatal("refetched within seconds of the last attempt")
	}
	// A cycle later the agent still runs on defaults: fetch.
	if !a.configChanged(now.Add(time.Minute)) {
		t.Fatal("an agent without its config did not ask for it when the server answered")
	}
}

func TestRevisionsFlappingBetweenServersAreBounded(t *testing.T) {
	tr := &revTransmitter{rev: "aaaa"}
	a := &Agent{logger: testLogger(), transmitter: tr, configFetched: true}
	now := time.Now()
	a.lastConfigFetch = now.Add(-time.Hour)
	a.configChanged(now) // first sighting

	fetches := 0
	for i := 0; i < 12; i++ { // two servers disagree for a minute
		tr.rev = []string{"bbbb", "aaaa"}[i%2]
		at := now.Add(time.Duration(i) * 5 * time.Second)
		if a.configChanged(at) {
			fetches++
			a.lastConfigFetch = at
		}
	}
	if fetches > 3 {
		t.Fatalf("%d config fetches in a minute", fetches)
	}
}
