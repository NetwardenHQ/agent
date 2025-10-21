// Package container provides container monitoring functionality for the Netwarden agent.
// It supports multiple container runtimes through a common interface.
package container

import (
	"context"
	"time"
)

// Container represents basic container information.
type Container struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Status  string            `json:"status"`
	Labels  map[string]string `json:"labels,omitempty"`
	Created time.Time         `json:"created"`
}

// ContainerStats represents container resource usage metrics.
type ContainerStats struct {
	ContainerID    string  `json:"container_id"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryUsage    uint64  `json:"memory_usage"`
	MemoryLimit    uint64  `json:"memory_limit"`
	NetworkRxBytes uint64  `json:"network_rx_bytes"`
	NetworkTxBytes uint64  `json:"network_tx_bytes"`
	DiskReadBytes  uint64  `json:"disk_read_bytes"`
	DiskWriteBytes uint64  `json:"disk_write_bytes"`
}

// RuntimeClient interface for container runtime implementations.
// This abstraction allows support for Docker, Podman, containerd, etc.
type RuntimeClient interface {
	// Name returns the name of the container runtime.
	Name() string

	// IsAvailable checks if the runtime is available and responding.
	IsAvailable() bool

	// ListContainers returns all containers managed by this runtime.
	ListContainers(ctx context.Context) ([]Container, error)

	// GetContainerStats retrieves resource usage statistics for a container.
	GetContainerStats(ctx context.Context, id string) (*ContainerStats, error)

	// Close performs cleanup and closes any connections.
	Close() error
}

// NoOpClient implements RuntimeClient for when no container runtime is available.
type NoOpClient struct{}

// Name returns the client name.
func (n *NoOpClient) Name() string {
	return "none"
}

// IsAvailable always returns false for the no-op client.
func (n *NoOpClient) IsAvailable() bool {
	return false
}

// ListContainers returns an empty list for the no-op client.
func (n *NoOpClient) ListContainers(ctx context.Context) ([]Container, error) {
	return nil, nil
}

// GetContainerStats returns nil for the no-op client.
func (n *NoOpClient) GetContainerStats(ctx context.Context, id string) (*ContainerStats, error) {
	return nil, nil
}

// Close is a no-op for the no-op client.
func (n *NoOpClient) Close() error {
	return nil
}
