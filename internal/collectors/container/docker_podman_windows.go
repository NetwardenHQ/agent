//go:build windows

package container

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// isNamedPipeAvailable checks if a Windows named pipe is available for connection.
func isNamedPipeAvailable(pipePath string) bool {
	// Try to dial the named pipe to check availability
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(pipePath, &timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// createDialContext creates a platform-specific dial context function.
func createDialContext(detectedPath string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.Contains(detectedPath, "pipe") {
			// Use winio for Windows named pipe connections
			return winio.DialPipe(detectedPath, nil)
		} else {
			// Use unix socket for compatibility (shouldn't happen on Windows)
			return net.Dial("unix", detectedPath)
		}
	}
}
