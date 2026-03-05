// Package http provides a shared HTTP client with connection pooling.
package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// globalClient is the shared HTTP client with optimized settings.
var globalClient *http.Client

// TLSConfig holds TLS configuration for the HTTP client.
type TLSConfig struct {
	SkipVerify bool   // Skip TLS certificate verification
	CACertPath string // Path to custom CA certificate (PEM)
}

func init() {
	// Initialize with default TLS settings (standard certificate validation).
	// Call InitClient() after config load to apply custom TLS settings.
	globalClient = buildClient(nil)
}

// InitClient reconfigures the global HTTP client with custom TLS settings.
// Call this after loading config to apply tls_skip_verify or tls_ca_cert.
func InitClient(tlsCfg *TLSConfig) error {
	client, err := buildClientWithTLS(tlsCfg)
	if err != nil {
		return err
	}
	globalClient = client
	return nil
}

func buildClient(tlsConfig *tls.Config) *http.Client {
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
		TLSClientConfig:     tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

func buildClientWithTLS(cfg *TLSConfig) (*http.Client, error) {
	if cfg == nil {
		return buildClient(nil), nil
	}

	var tlsConfig *tls.Config

	if cfg.SkipVerify || cfg.CACertPath != "" {
		tlsConfig = &tls.Config{}
	}

	if cfg.SkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", cfg.CACertPath)
		}
		tlsConfig.RootCAs = pool
	}

	return buildClient(tlsConfig), nil
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
