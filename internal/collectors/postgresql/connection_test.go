package postgresql

import (
	"context"
	"io"
	"log/slog"
	"testing"

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
