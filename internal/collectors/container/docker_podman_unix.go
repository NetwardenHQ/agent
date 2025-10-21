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
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Use unix socket for Linux/macOS
		return net.Dial("unix", detectedPath)
	}
}
