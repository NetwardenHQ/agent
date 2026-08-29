package agent

import (
	"io"
	"log/slog"
)

// testLogger returns a logger that discards output, so tests stay quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
