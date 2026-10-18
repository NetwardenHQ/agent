package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

func serverTransmitter(t *testing.T, h http.HandlerFunc) *HTTPTransmitter {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tr := &HTTPTransmitter{
		config:     &config.Config{TenantID: "abcdefghij", ServerURL: srv.URL},
		logger:     testLogger(),
		version:    "2.1.0",
		hostname:   "test-host",
		httpClient: srv.Client(),
	}
	tr.lastLatencyMs.Store(-1)
	return tr
}

var oneMetric = []metrics.Metric{{Name: "m", Value: 1, Timestamp: time.Now()}}

func TestRateLimitIsHonoredABoundedNumberOfTimes(t *testing.T) {
	var requests atomic.Int32
	tr := serverTransmitter(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	var waits []time.Duration
	old := rateLimitSleep
	rateLimitSleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	t.Cleanup(func() { rateLimitSleep = old })

	if err := tr.Send(context.Background(), oneMetric, nil); err == nil {
		t.Fatal("a persistent 429 must fail the send")
	}
	if n := requests.Load(); n != 1+maxRateLimitRetries {
		t.Fatalf("%d requests for one Send, want %d", n, 1+maxRateLimitRetries)
	}
	for _, w := range waits {
		if w != maxRetryAfter {
			t.Fatalf("Retry-After of a day honored as %v, want the %v cap", w, maxRetryAfter)
		}
	}
}

func TestRequestTimeoutAndTooEarlyAreRetried(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooEarly} {
		var requests atomic.Int32
		tr := serverTransmitter(t, func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 1 {
				w.WriteHeader(status)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		if err := tr.Send(context.Background(), oneMetric, nil); err != nil {
			t.Fatalf("status %d must be retried, got %v", status, err)
		}
		if requests.Load() != 2 {
			t.Fatalf("status %d: %d requests, want 2", status, requests.Load())
		}
	}
}

func TestBackoffSkipIsNotRecordedAsAnAttempt(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "spool")
	a := &Agent{logger: testLogger(), transmitter: newTestTransmitter(t)}
	a.state = newStateFile(spoolDir, "2.1.0", time.Now(), testLogger())

	tr := a.transmitter.(*HTTPTransmitter)
	tr.consecutiveFailures, tr.lastFailure = 3, time.Now()
	err := tr.Send(context.Background(), oneMetric, nil)
	if !errors.Is(err, errBackingOff) {
		t.Fatalf("expected the backoff skip, got %v", err)
	}
	a.recordAttempt(time.Now(), err)
	if a.state.doc.LastPostAttemptAt != nil {
		t.Fatal("a skipped send must not be recorded as a post attempt")
	}

	a.recordAttempt(time.Now(), errors.New("request failed"))
	if a.state.doc.LastPostAttemptAt == nil {
		t.Fatal("a real failed attempt must still be recorded")
	}
}
