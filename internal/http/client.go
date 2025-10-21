// Package http provides a shared HTTP client with connection pooling.
package http

import (
	"net"
	"net/http"
	"time"
)

// globalClient is the shared HTTP client with optimized settings.
var globalClient *http.Client

func init() {
	// Create transport with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	globalClient = &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

// GetClient returns the global HTTP client.
func GetClient() *http.Client {
	return globalClient
}

// GetClientWithTimeout returns a client with a custom timeout.
// Note: This still uses the shared transport for connection pooling.
func GetClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: globalClient.Transport,
		Timeout:   timeout,
	}
}
