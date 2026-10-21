package mysql

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
		config:         config.DatabaseConfig{MySQLHost: "127.0.0.1:1", MySQLUser: "monitor"},
		hostname:       "test",
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:          newMySQLCache(),
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
	if got["mysql_up"] != 1 || got["mysql_connection_failed"] != 1 {
		t.Fatalf("got %v, want mysql_up=1 and mysql_connection_failed=1", got)
	}
}

func TestCollectReportsDown(t *testing.T) {
	c := &Collector{hostname: "test", logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cache: newMySQLCache(),
		active: true, processRunning: func() bool { return false }}
	ms, _ := c.Collect(context.Background())
	if len(ms) != 1 || ms[0].Name != "mysql_up" || ms[0].Value != 0 {
		t.Fatalf("got %v, want only mysql_up=0", ms)
	}
}
