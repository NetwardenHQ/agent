//go:build !windows

package container

import (
	"context"
	"net"
)

// isNamedPipeAvailable always returns false on Unix systems.
func isNamedPipeAvailable(pipePath string) bool {
	return false
}

// createDialContext creates a platform-specific dial context function.
func createDialContext(detectedPath string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Unix socket on Linux/macOS. DialContext so a request's deadline
		// or cancellation also bounds the connect.
		return dialer.DialContext(ctx, "unix", detectedPath)
	}
}
