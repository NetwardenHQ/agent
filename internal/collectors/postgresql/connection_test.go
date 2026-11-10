package postgresql

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
)

// A server that runs but cannot be reached must say so, not go silent.
func TestCollectReportsConnectionFailure(t *testing.T) {
	c := &Collector{
		config:         config.DatabaseConfig{PostgreSQLHost: "127.0.0.1:1", PostgreSQLUser: "monitor"},
		hostname:       "test",
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		active:         true,
		processRunning: func() bool { return true },
	}
	if !c.Enabled() {
		t.Fatal("a configured collector must stay enabled while the server is unreachable")
	}
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, m := range ms {
		got[m.Name] = m.Value
	}
	if got["postgresql_up"] != 1 || got["postgresql_connection_failed"] != 1 {
		t.Fatalf("got %v, want postgresql_up=1 and postgresql_connection_failed=1", got)
	}
}

func TestCollectReportsDown(t *testing.T) {
	c := &Collector{hostname: "test", logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		active: true, processRunning: func() bool { return false }}
	ms, _ := c.Collect(context.Background())
	if len(ms) != 1 || ms[0].Name != "postgresql_up" || ms[0].Value != 0 {
		t.Fatalf("got %v, want only postgresql_up=0", ms)
	}
}

// A database installed after the agent started is found without a restart,
// and looking for it costs one check per interval, not one per cycle.
func TestInactiveCollectorLooksAgainForAServer(t *testing.T) {
	checks := 0
	found := false
	c := &Collector{hostname: "test", logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		lastDetect: time.Now(), detect: func() bool { checks++; return found }}

	for i := 0; i < 5; i++ {
		if c.Enabled() {
			t.Fatal("enabled with no server")
		}
	}
	if checks != 0 {
		t.Fatalf("looked for a server %d times inside the interval", checks)
	}

	c.lastDetect = time.Now().Add(-redetectEvery() - time.Second)
	if c.Enabled() || checks != 1 {
		t.Fatalf("after the interval: checks=%d", checks)
	}
	if c.Enabled(); checks != 1 {
		t.Fatalf("looked again straight away: checks=%d", checks)
	}

	found = true
	c.lastDetect = time.Now().Add(-redetectEvery() - time.Second)
	if !c.Enabled() {
		t.Fatal("a server that appeared was not picked up")
	}
	// Once monitoring, it stays on and stops looking.
	found = false
	c.lastDetect = time.Now().Add(-2 * redetectEvery())
	if !c.Enabled() || checks != 2 {
		t.Fatalf("active collector: enabled=%v checks=%d", c.Enabled(), checks)
	}
}
