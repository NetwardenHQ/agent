// Package registry provides a simple collector registry for managing metric collectors.
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"netwarden/internal/collectors/pool"
	"netwarden/internal/metrics"
)

// Registry is a simplified collector registry for managing metric collectors.
type Registry struct {
	collectors     []metrics.Collector
	mutex          sync.RWMutex
	logger         *slog.Logger
	workerPool     *pool.WorkerPool
	poolStarted    bool
	poolStartMutex sync.Mutex
}

// NewRegistry creates a new registry with concurrent collection support.
func NewRegistry(logger *slog.Logger) metrics.Registry {
	if logger == nil {
		logger = slog.Default()
	}

	// Create worker pool for concurrent collection (but don't start it yet)
	poolConfig := pool.DefaultWorkerPoolConfig()
	poolConfig.Logger = logger.With("component", "worker_pool")
	workerPool := pool.NewWorkerPool(poolConfig)

	return &Registry{
		collectors:  make([]metrics.Collector, 0),
		logger:      logger,
		workerPool:  workerPool,
		poolStarted: false,
	}
}

// Register adds a collector to the registry.
func (r *Registry) Register(collector metrics.Collector) error {
	if collector == nil {
		return fmt.Errorf("collector cannot be nil")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check for duplicates
	name := collector.Name()
	for _, existing := range r.collectors {
		if existing.Name() == name {
			return fmt.Errorf("collector %s already registered", name)
		}
	}

	r.collectors = append(r.collectors, collector)
	r.logger.Info("registered collector", "name", name)
	return nil
}

// ensureWorkerPoolStarted starts the worker pool if not already started (lazy initialization).
func (r *Registry) ensureWorkerPoolStarted(ctx context.Context) error {
	// Fast path: check if already started
	if r.poolStarted {
		return nil
	}

	// Slow path: acquire lock and start pool
	r.poolStartMutex.Lock()
	defer r.poolStartMutex.Unlock()

	// Double-check pattern
	if r.poolStarted {
		return nil
	}

	// Start the worker pool
	if err := r.workerPool.Start(ctx); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}

	r.poolStarted = true
	r.logger.Info("worker pool started on first collection")
	return nil
}

// Unregister removes a collector from the registry.
func (r *Registry) Unregister(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, collector := range r.collectors {
		if collector.Name() == name {
			// Close the collector
			if err := collector.Close(); err != nil {
				r.logger.Warn("error closing collector", "name", name, "error", err)
			}
			// Remove from slice
			r.collectors = append(r.collectors[:i], r.collectors[i+1:]...)
			r.logger.Info("unregistered collector", "name", name)
			return nil
		}
	}

	return fmt.Errorf("collector %s not found", name)
}

// CollectAll gathers metrics from all enabled collectors concurrently.
func (r *Registry) CollectAll(ctx context.Context) ([]metrics.Metric, error) {
	r.mutex.RLock()
	// Filter enabled collectors and make a copy to avoid holding lock during collection
	var enabledCollectors []metrics.Collector
	for _, collector := range r.collectors {
		if collector.Enabled() {
			enabledCollectors = append(enabledCollectors, collector)
		}
	}
	r.mutex.RUnlock()

	if len(enabledCollectors) == 0 {
		r.logger.Debug("no enabled collectors found")
		return []metrics.Metric{}, nil
	}

	// Start worker pool on first use (lazy initialization)
	if err := r.ensureWorkerPoolStarted(ctx); err != nil {
		return nil, fmt.Errorf("failed to start worker pool: %w", err)
	}

	r.logger.Debug("starting concurrent collection", "enabled_collectors", len(enabledCollectors))

	// Use worker pool for concurrent collection
	results := r.workerPool.CollectAll(ctx, enabledCollectors)

	// Convert results to metrics and aggregate errors
	var allMetrics []metrics.Metric
	var collectionErrors []string

	for _, result := range results {
		if result.Error != nil {
			r.logger.Warn("collector failed",
				"collector", result.CollectorName,
				"error", result.Error,
				"duration", result.Duration)
			collectionErrors = append(collectionErrors,
				fmt.Sprintf("%s: %v", result.CollectorName, result.Error))
			continue
		}
		allMetrics = append(allMetrics, result.Metrics...)
	}

	// Return aggregated error if any collectors failed
	if len(collectionErrors) > 0 {
		return allMetrics, fmt.Errorf("partial collection failure (%d collectors failed): %v",
			len(collectionErrors), collectionErrors)
	}

	return allMetrics, nil
}

// ListCollectors returns the names of all registered collectors.
func (r *Registry) ListCollectors() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	names := make([]string, len(r.collectors))
	for i, collector := range r.collectors {
		names[i] = collector.Name()
	}
	return names
}

// GetCollector returns a collector by name, or nil if not found.
func (r *Registry) GetCollector(name string) metrics.Collector {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, collector := range r.collectors {
		if collector.Name() == name {
			return collector
		}
	}
	return nil
}

// Close shuts down all collectors and the worker pool.
func (r *Registry) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Stop the worker pool first (only if it was started)
	if r.workerPool != nil && r.poolStarted {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.workerPool.Stop(ctx); err != nil {
			r.logger.Warn("error stopping worker pool", "error", err)
		}
		r.workerPool = nil
		r.poolStarted = false
	}

	// Close all collectors
	var lastError error
	for _, collector := range r.collectors {
		if err := collector.Close(); err != nil {
			r.logger.Error("error closing collector", "name", collector.Name(), "error", err)
			lastError = err
		}
	}

	r.collectors = nil
	r.logger.Info("registry closed")
	return lastError
}

// HealthCheck checks the health of all collectors.
func (r *Registry) HealthCheck(ctx context.Context) map[string]error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	healthResults := make(map[string]error)
	for _, collector := range r.collectors {
		if healthChecker, ok := collector.(metrics.HealthChecker); ok {
			healthResults[collector.Name()] = healthChecker.HealthCheck(ctx)
		}
	}
	return healthResults
}

// GetStats returns empty stats (not needed in simplified version).
func (r *Registry) GetStats() metrics.RegistryStats {
	return metrics.RegistryStats{}
}
