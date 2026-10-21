// Package container provides container monitoring functionality for the Netwarden agent.
// It supports multiple container runtimes through a common interface.
package container

import (
	"context"
	"strings"
	"time"
)

// Container represents basic container information.
type Container struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"` // reference, e.g. "nginx:1.27" or "nginx@sha256:..."
	// ImageID is the local image ID: the digest of the image's config
	// object, always "sha256:<hex>" (see normalizeImageID). It is NOT the
	// registry (manifest / repo) digest that appears after "@" in a
	// reference; the two differ for the same image.
	ImageID string            `json:"image_id"`
	Status  string            `json:"status"`
	Labels  map[string]string `json:"labels,omitempty"`
	Created time.Time         `json:"created"`

	// Health is the health check state ("healthy", "unhealthy", "starting"),
	// or "" for a container without a health check.
	Health string `json:"health,omitempty"`
	// ExitCode is set for a container that has exited, when the runtime says.
	ExitCode *int `json:"exit_code,omitempty"`
	// Restarts is the restart count, when the runtime lists it (Podman does,
	// Docker's list endpoint does not).
	Restarts *int `json:"restarts,omitempty"`
}

// ContainerStats represents container resource usage metrics.
//
// Each group carries a Known flag: a runtime that could not read a figure
// (podman prints "--", a host-network container has no interfaces) leaves it
// false and the collector emits no series, rather than a 0 that would graph
// as a measurement.
type ContainerStats struct {
	ContainerID string `json:"container_id"`
	// CPUPercent uses the docker/podman stats scale: 100 = one CPU core
	// fully busy, so a container using four cores reads 400.
	CPUPercent float64 `json:"cpu_percent"`
	CPUKnown   bool    `json:"-"`
	// MemoryLimit is 0 when the runtime did not report one.
	MemoryUsage    uint64 `json:"memory_usage"`
	MemoryLimit    uint64 `json:"memory_limit"`
	MemoryKnown    bool   `json:"-"`
	NetworkRxBytes uint64 `json:"network_rx_bytes"`
	NetworkTxBytes uint64 `json:"network_tx_bytes"`
	NetworkKnown   bool   `json:"-"`
	DiskReadBytes  uint64 `json:"disk_read_bytes"`
	DiskWriteBytes uint64 `json:"disk_write_bytes"`
	DiskKnown      bool   `json:"-"`
}

// normalizeImageID returns an image ID in the "sha256:<hex>" form the Docker
// API uses. `podman ps --format json` reports the bare hex; without this the
// same image would be two inventory entries depending on which client
// answered.
func normalizeImageID(id string) string {
	if id == "" || strings.Contains(id, ":") {
		return id
	}
	return "sha256:" + id
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
