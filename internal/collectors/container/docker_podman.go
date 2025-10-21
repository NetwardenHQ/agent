// Package container provides Docker/Podman compatible client implementation for container monitoring.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DockerCompatibleClient implements RuntimeClient for Docker/Podman communication.
// Both Docker and Podman expose compatible REST APIs, so we can use the same client.
type DockerCompatibleClient struct {
	socketPath  string
	httpClient  *http.Client
	runtimeType string // "docker" or "podman"
	runtimeName string // detected runtime name
	// Availability caching to prevent repeated expensive checks
	availabilityMutex  sync.RWMutex
	cachedAvailability bool
	cacheExpiry        time.Time
}

// NewDockerClient creates a new Docker client with Unix socket connection.
// Maintained for backward compatibility.
func NewDockerClient(socketPath string) *DockerCompatibleClient {
	return NewDockerCompatibleClient(socketPath)
}

// NewDockerCompatibleClient creates a client that works with Docker or Podman.
func NewDockerCompatibleClient(socketPath string) *DockerCompatibleClient {
	var detectedPath string
	var runtimeType string

	if socketPath != "" {
		// Use explicitly provided socket path
		detectedPath = socketPath
		runtimeType = "unknown" // Will be detected on first use
	} else {
		// Try to detect available runtime
		detectedPath, runtimeType = detectContainerRuntime()
	}

	return &DockerCompatibleClient{
		socketPath:  detectedPath,
		runtimeType: runtimeType,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: createDialContext(detectedPath),
			},
		},
	}
}

// Name returns the detected runtime name.
func (d *DockerCompatibleClient) Name() string {
	if d.runtimeName != "" {
		return d.runtimeName
	}
	return d.runtimeType
}

// IsAvailable checks if the container runtime is available and responding.
// Uses caching to prevent expensive repeated checks.
func (d *DockerCompatibleClient) IsAvailable() bool {
	// Check cache first (5-minute cache)
	d.availabilityMutex.RLock()
	if time.Now().Before(d.cacheExpiry) {
		result := d.cachedAvailability
		d.availabilityMutex.RUnlock()
		return result
	}
	d.availabilityMutex.RUnlock()

	// Need to check availability
	d.availabilityMutex.Lock()
	defer d.availabilityMutex.Unlock()

	// Double-check pattern - another goroutine might have updated the cache
	if time.Now().Before(d.cacheExpiry) {
		return d.cachedAvailability
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use generic host name since both Docker and Podman APIs are compatible
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://runtime/version", nil)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Cache negative result for shorter time (1 minute)
		d.cachedAvailability = false
		d.cacheExpiry = time.Now().Add(1 * time.Minute)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		// Try to detect runtime type from version response if not already known
		if d.runtimeType == "unknown" || d.runtimeName == "" {
			d.detectRuntimeFromResponse(resp)
		}
		// Cache positive result for longer time (5 minutes)
		d.cachedAvailability = true
		d.cacheExpiry = time.Now().Add(5 * time.Minute)
		return true
	}

	// Cache negative result for shorter time (1 minute)
	d.cachedAvailability = false
	d.cacheExpiry = time.Now().Add(1 * time.Minute)
	return false
}

// ListContainers retrieves all containers from the runtime daemon.
func (d *DockerCompatibleClient) ListContainers(ctx context.Context) ([]Container, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://runtime/containers/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s API returned status %d", d.Name(), resp.StatusCode)
	}

	var apiContainers []containerFromAPI
	if err := json.NewDecoder(resp.Body).Decode(&apiContainers); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	containers := make([]Container, len(apiContainers))
	for i, ac := range apiContainers {
		containers[i] = Container{
			ID:      ac.ID,
			Name:    cleanContainerName(ac.Names[0]), // Remove leading /
			Image:   ac.Image,
			Status:  ac.State,
			Labels:  ac.Labels,
			Created: time.Unix(ac.Created, 0),
		}
	}

	return containers, nil
}

// GetContainerStats retrieves resource usage statistics for a container.
func (d *DockerCompatibleClient) GetContainerStats(ctx context.Context, id string) (*ContainerStats, error) {
	url := fmt.Sprintf("http://runtime/containers/%s/stats?stream=false", id)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s stats API returned status %d", d.Name(), resp.StatusCode)
	}

	var statsFromAPI statsFromAPI
	if err := json.NewDecoder(resp.Body).Decode(&statsFromAPI); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}

	return convertAPIStats(id, &statsFromAPI), nil
}

// Close performs cleanup (HTTP client doesn't need explicit closing).
func (d *DockerCompatibleClient) Close() error {
	return nil
}

// containerFromAPI represents a container from Docker/Podman API response.
// Both APIs use the same format for container listing.
type containerFromAPI struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
}

// statsFromAPI represents container statistics from Docker/Podman API.
// Both APIs use compatible formats for stats.
type statsFromAPI struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats struct {
		IoServiceBytesRecursive []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

// cleanContainerName removes the leading "/" from Docker container names.
func cleanContainerName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}

// convertAPIStats converts Docker/Podman API stats to our internal ContainerStats format.
func convertAPIStats(containerID string, stats *statsFromAPI) *ContainerStats {
	// Calculate CPU percentage
	cpuPercent := 0.0
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
	if systemDelta > 0 {
		cpuPercent = (cpuDelta / systemDelta) * 100.0
	}

	// Calculate network totals
	var networkRx, networkTx uint64
	for _, network := range stats.Networks {
		networkRx += network.RxBytes
		networkTx += network.TxBytes
	}

	// Calculate disk I/O totals
	var diskRead, diskWrite uint64
	for _, io := range stats.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(io.Op) {
		case "read":
			diskRead += io.Value
		case "write":
			diskWrite += io.Value
		}
	}

	return &ContainerStats{
		ContainerID:    containerID,
		CPUPercent:     cpuPercent,
		MemoryUsage:    stats.MemoryStats.Usage,
		MemoryLimit:    stats.MemoryStats.Limit,
		NetworkRxBytes: networkRx,
		NetworkTxBytes: networkTx,
		DiskReadBytes:  diskRead,
		DiskWriteBytes: diskWrite,
	}
}

// detectContainerRuntime tries to find an available container runtime.
// Returns the socket path and runtime type.
func detectContainerRuntime() (string, string) {
	// Try Windows Docker Desktop named pipe first
	if runtime.GOOS == "windows" {
		pipePath := `\\.\pipe\docker_engine`
		if isNamedPipeAvailable(pipePath) {
			return pipePath, "docker"
		}
	}

	// Try Docker first (Linux/macOS)
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return "/var/run/docker.sock", "docker"
	}

	// Try Podman system socket
	if _, err := os.Stat("/run/podman/podman.sock"); err == nil {
		return "/run/podman/podman.sock", "podman"
	}

	// Try Podman user socket
	if currentUser, err := user.Current(); err == nil {
		userSocket := fmt.Sprintf("/run/user/%s/podman/podman.sock", currentUser.Uid)
		if _, err := os.Stat(userSocket); err == nil {
			return userSocket, "podman"
		}
	}

	// Default based on platform
	if runtime.GOOS == "windows" {
		return `\\.\pipe\docker_engine`, "docker"
	}
	return "/var/run/docker.sock", "docker"
}

// detectRuntimeFromResponse attempts to detect the runtime from version response.
func (d *DockerCompatibleClient) detectRuntimeFromResponse(resp *http.Response) {
	// Reset response body to read it
	resp.Body.Close()

	// Make a fresh request to get version info
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://runtime/version", nil)
	versionResp, err := d.httpClient.Do(req)
	if err != nil {
		return
	}
	defer versionResp.Body.Close()

	var versionInfo struct {
		Components []struct {
			Name    string `json:"Name"`
			Version string `json:"Version"`
		} `json:"Components"`
		Engine struct {
			Name string `json:"Name"`
		} `json:"Engine"`
		Platform struct {
			Name string `json:"Name"`
		} `json:"Platform"`
	}

	if err := json.NewDecoder(versionResp.Body).Decode(&versionInfo); err != nil {
		return
	}

	// Try to detect from various fields
	if strings.Contains(strings.ToLower(versionInfo.Platform.Name), "podman") {
		d.runtimeType = "podman"
		d.runtimeName = "podman"
	} else if len(versionInfo.Components) > 0 {
		// Check components for podman
		for _, component := range versionInfo.Components {
			if strings.Contains(strings.ToLower(component.Name), "podman") {
				d.runtimeType = "podman"
				d.runtimeName = "podman"
				return
			}
		}
		// Default to docker if no podman found
		d.runtimeType = "docker"
		d.runtimeName = "docker"
	} else {
		// Fallback detection
		d.runtimeType = "docker"
		d.runtimeName = "docker"
	}
}
