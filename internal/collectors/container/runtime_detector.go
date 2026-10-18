// Package container provides runtime detection for container monitoring.
package container

import (
	"log/slog"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
)

// RuntimeDetector handles automatic detection of available container runtimes.
type RuntimeDetector struct {
	logger *slog.Logger
}

// NewRuntimeDetector creates a new runtime detector.
func NewRuntimeDetector(logger *slog.Logger) *RuntimeDetector {
	return &RuntimeDetector{
		logger: logger,
	}
}

// DetectRuntime finds and creates the best available container runtime client.
func (r *RuntimeDetector) DetectRuntime(cfg config.ContainerConfig) RuntimeClient {
	if cfg.ContainerRuntime != "auto" {
		return r.createSpecificRuntime(cfg.ContainerRuntime, cfg.ContainerSocket)
	}

	r.logger.Debug("auto-detecting container runtime")

	// Try runtimes in order of preference: Docker → Podman
	runtimes := []struct {
		name   string
		create func() RuntimeClient
	}{
		{
			name: "docker/podman",
			create: func() RuntimeClient {
				// The unified client will auto-detect Docker vs Podman
				return NewDockerCompatibleClient(cfg.ContainerSocket)
			},
		},
		{
			// Podman without an API socket (`podman.socket` ships disabled
			// on Debian and Ubuntu). Tried last because the socket API is
			// cheaper than forking a process per collection.
			name:   "podman-cli",
			create: func() RuntimeClient { return newPodmanCLIClientIfSupported() },
		},
	}

	for _, runtime := range runtimes {
		r.logger.Debug("trying runtime", "runtime", runtime.name)

		client := runtime.create()
		if client.IsAvailable() {
			r.logger.Info("detected container runtime", "runtime", client.Name())
			return client
		}

		// Clean up failed client
		client.Close()
	}

	r.logger.Info("no container runtime detected")
	return &NoOpClient{}
}

// createSpecificRuntime creates a client for a specific runtime type.
func (r *RuntimeDetector) createSpecificRuntime(runtimeType, socketPath string) RuntimeClient {
	r.logger.Debug("creating specific runtime client", "runtime", runtimeType)

	switch runtimeType {
	case "docker", "podman":
		// Both are handled by the same compatible client
		client := NewDockerCompatibleClient(socketPath)
		if !client.IsAvailable() {
			r.logger.Warn("container runtime not available", "runtime", runtimeType)
		}
		return client

	default:
		r.logger.Warn("unsupported container runtime", "runtime", runtimeType)
		return &NoOpClient{}
	}
}

// RuntimeMonitor re-checks the runtime on a throttle and, in auto mode,
// switches to another runtime when the current one disappears. Safe for
// concurrent use: Enabled() and Snapshots() ask it from the agent goroutine
// while Collect() runs on a collection goroutine.
type RuntimeMonitor struct {
	mu            sync.Mutex
	client        RuntimeClient
	logger        *slog.Logger
	detector      *RuntimeDetector
	config        config.ContainerConfig
	available     bool
	lastCheck     time.Time
	checkInterval time.Duration
}

// NewRuntimeMonitor creates a new runtime monitor.
func NewRuntimeMonitor(client RuntimeClient, detector *RuntimeDetector, config config.ContainerConfig, logger *slog.Logger) *RuntimeMonitor {
	return &RuntimeMonitor{
		client:        client,
		logger:        logger,
		detector:      detector,
		config:        config,
		available:     client.IsAvailable(),
		lastCheck:     time.Now(),
		checkInterval: 30 * time.Second, // Check every 30 seconds
	}
}

// IsAvailable reports whether the runtime is currently available, re-checking
// at most once per checkInterval and failing over in auto mode.
func (rm *RuntimeMonitor) IsAvailable() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	if now.Sub(rm.lastCheck) < rm.checkInterval {
		return rm.available
	}
	rm.lastCheck = now

	// Quick availability check with timeout
	available := rm.client.IsAvailable()

	if available != rm.available {
		if available {
			rm.logger.Info("container runtime became available", "runtime", rm.client.Name())
		} else {
			rm.logger.Warn("container runtime became unavailable", "runtime", rm.client.Name())

			// Try to detect a new runtime if current one failed and auto-detection is enabled
			if rm.config.ContainerRuntime == "auto" {
				rm.logger.Info("attempting to detect alternative runtime")
				newClient := rm.detector.DetectRuntime(rm.config)
				if newClient.Name() != "none" && newClient.IsAvailable() {
					rm.logger.Info("switched to alternative runtime",
						"old_runtime", rm.client.Name(),
						"new_runtime", newClient.Name())
					rm.client.Close()
					rm.client = newClient
					available = true
				}
			}
		}
		rm.available = available
	}

	return rm.available
}

// GetClient returns the current runtime client.
func (rm *RuntimeMonitor) GetClient() RuntimeClient {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.client
}

// Close shuts down the monitor and its client.
func (rm *RuntimeMonitor) Close() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.client != nil {
		return rm.client.Close()
	}
	return nil
}
