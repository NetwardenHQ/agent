// Package metrics provides metric types and interfaces for the Netwarden agent.
package metrics

import (
	"context"
	"time"
)

// MetricType represents the type of metric being collected.
type MetricType string

const (
	// MetricTypeGauge represents a metric that can go up or down.
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeCounter represents a metric that only increases.
	MetricTypeCounter MetricType = "counter"
	// MetricTypeHistogram represents a metric that samples observations.
	MetricTypeHistogram MetricType = "histogram"
)

// Metric represents a single metric data point with associated metadata.
// All fields are strongly typed to eliminate interface{} usage.
type Metric struct {
	// Timestamp is when this metric was collected.
	Timestamp time.Time `json:"timestamp"`

	// Type indicates the metric type (gauge, counter, histogram).
	Type MetricType `json:"type"`

	// Name is the metric name following Prometheus naming conventions.
	Name string `json:"name"`

	// Value is the numeric value of the metric.
	Value float64 `json:"value"`

	// Labels provide dimensional metadata for the metric.
	Labels map[string]string `json:"labels"`
}

// Collector defines the interface that all metric collectors must implement.
type Collector interface {
	// Name returns the unique name of this collector.
	Name() string

	// Collect gathers metrics and returns them. The context allows for
	// cancellation and timeout handling.
	Collect(ctx context.Context) ([]Metric, error)

	// Enabled returns true if this collector should be active.
	Enabled() bool

	// Close performs any necessary cleanup. Collectors should be safe
	// to call Close multiple times.
	Close() error
}

// Snapshot is a structured, non-time-series observation shipped alongside
// metrics in the /agent/data payload. Unlike a Metric (one float per point),
// a snapshot carries a whole object — an sshd_config audit, the listening
// socket table, the installed-package inventory — that the platform persists
// verbatim into host_security_snapshots and feeds to its findings evaluator.
//
// Type MUST match one of the snapshot types the server accepts (see the
// z.enum in platform/app/api/agent/data/route.ts and the SnapshotType union
// in platform/lib/security/findings-types.ts). Unknown types are rejected by
// the endpoint's schema validation, failing the whole request — so only emit
// types the server knows.
type Snapshot struct {
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// Snapshot type identifiers. Keep in lockstep with the server-side
// SnapshotType union; adding one here without adding it there breaks
// ingestion for the entire payload, not just the snapshot.
const (
	SnapshotSSHConfig         = "ssh_config"
	SnapshotListeningPorts    = "listening_ports"
	SnapshotInstalledPackages = "installed_packages"
	SnapshotCISResults        = "cis_results"
)

// SnapshotProvider is an optional interface for collectors that produce
// structured snapshots in addition to metrics.
//
// Contract: Snapshots() is called by the registry immediately after
// CollectAll() completes, and returns whatever the most recent Collect()
// produced. Returning nil is normal and means "nothing new this cycle" —
// collectors that run on a slower cadence than the reporting interval (the
// package inventory, for instance) return nil on intervening cycles rather
// than re-shipping an unchanged payload. Implementations must be safe for
// concurrent use, since Collect() runs on the worker pool.
type SnapshotProvider interface {
	Snapshots() []Snapshot
}

// HealthChecker is an optional interface that collectors can implement
// to provide health status information.
type HealthChecker interface {
	// HealthCheck returns nil if the collector is healthy, or an error
	// describing the health issue.
	HealthCheck(ctx context.Context) error
}

// ConnectionManager is an interface for collectors that manage connections
// to external services (like libvirt, Docker, etc.).
type ConnectionManager interface {
	// Connect establishes connection(s) to the external service.
	Connect(ctx context.Context) error

	// Disconnect cleanly closes connection(s).
	Disconnect() error

	// IsConnected returns true if the connection is active and healthy.
	IsConnected() bool
}

// Registry manages a collection of metric collectors and orchestrates their execution.
type Registry interface {
	// Register adds a collector to the registry with validation.
	Register(collector Collector) error

	// Unregister removes a collector from the registry.
	Unregister(name string) error

	// CollectAll gathers metrics from all enabled collectors.
	// Collection happens concurrently with proper error handling.
	CollectAll(ctx context.Context) ([]Metric, error)

	// ListCollectors returns the names of all registered collectors.
	ListCollectors() []string

	// GetCollector returns a collector by name, or nil if not found.
	GetCollector(name string) Collector

	// Snapshots gathers structured snapshots from every registered collector
	// implementing SnapshotProvider. Call after CollectAll() — it returns
	// what the last collection cycle produced, it does not itself collect.
	Snapshots() []Snapshot

	// HealthCheck checks the health of all collectors that implement HealthChecker.
	HealthCheck(ctx context.Context) map[string]error

	// Close shuts down all collectors gracefully.
	Close() error

	// GetStats returns registry statistics for monitoring.
	GetStats() RegistryStats
}

// RegistryStats provides registry operational statistics.
type RegistryStats struct {
	// TotalCollectors is the number of registered collectors.
	TotalCollectors int `json:"total_collectors"`

	// EnabledCollectors is the number of enabled collectors.
	EnabledCollectors int `json:"enabled_collectors"`

	// LastCollectionDuration is the time taken for the last collection cycle.
	LastCollectionDuration time.Duration `json:"last_collection_duration"`

	// TotalCollections is the total number of collection cycles performed.
	TotalCollections int64 `json:"total_collections"`

	// FailedCollections is the number of failed collection cycles.
	FailedCollections int64 `json:"failed_collections"`

	// LastCollectionTime is when the last collection occurred.
	LastCollectionTime time.Time `json:"last_collection_time"`
}
