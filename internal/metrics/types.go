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
// a snapshot carries a whole object, such as an sshd_config audit, the
// listening socket table or the installed-package inventory, which the
// platform stores verbatim and evaluates.
//
// Type must be one of the snapshot types the server accepts. The server
// validates the payload as a whole, so an unknown type fails the entire
// request.
type Snapshot struct {
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// Snapshot type identifiers. They must match the types the server accepts;
// one the server does not know breaks ingestion of the entire payload, not
// just the snapshot.
const (
	SnapshotSSHConfig            = "ssh_config"
	SnapshotListeningPorts       = "listening_ports"
	SnapshotInstalledPackages    = "installed_packages"
	SnapshotCISResults           = "cis_results"
	SnapshotContainerImages      = "container_images"
	SnapshotFileIntegrity        = "file_integrity"
	SnapshotK8sHealthDelta       = "k8s_health_delta"
	SnapshotK8sClusterHealth     = "k8s_cluster_health"
	SnapshotK8sComponentVersions = "k8s_component_versions"
	SnapshotK8sInventory         = "k8s_inventory"
	SnapshotK8sCronJobs          = "k8s_cronjobs"
	SnapshotK8sCNPG              = "k8s_cnpg"
	SnapshotK8sIngress           = "k8s_ingress"
	SnapshotEvents               = "events"
	SnapshotNetworkExposure      = "network_exposure"
	SnapshotDeviceIdentity       = "device_identity"
)

// SnapshotProvider is an optional interface for collectors that produce
// structured snapshots in addition to metrics.
//
// Contract: Snapshots() is called by the registry immediately after
// CollectAll() completes, and returns whatever the most recent Collect()
// produced. Returning nil is normal and means "nothing new this cycle":
// collectors that run on a slower cadence than the reporting interval (the
// package inventory, for instance) return nil on intervening cycles rather
// than re-shipping an unchanged payload. Implementations must be safe for
// concurrent use: Collect() runs on a collection goroutine and Snapshots()
// on the agent's.
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

// Registry manages a collection of metric collectors and runs collection cycles.
type Registry interface {
	// Register adds a collector. Names must be unique.
	Register(collector Collector) error

	// CollectAll runs every enabled collector for one cycle and returns the
	// combined metrics. Collectors run concurrently.
	CollectAll(ctx context.Context) ([]Metric, error)

	// ListCollectors returns the names of all registered collectors.
	ListCollectors() []string

	// GetCollector returns a collector by name, or nil if not found.
	GetCollector(name string) Collector

	// Snapshots gathers structured snapshots from every registered collector
	// implementing SnapshotProvider. Call it after CollectAll(): it returns
	// what the last collection cycle produced and does not collect itself.
	Snapshots() []Snapshot

	// HealthCheck checks the health of all collectors that implement HealthChecker.
	HealthCheck(ctx context.Context) map[string]error

	// Close shuts down all collectors gracefully.
	Close() error
}
