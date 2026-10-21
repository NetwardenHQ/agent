// Package container provides Docker/Podman compatible client implementation for container monitoring.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DockerCompatibleClient implements RuntimeClient for Docker/Podman communication.
// Docker and Podman expose compatible REST APIs, so one client serves both.
type DockerCompatibleClient struct {
	socketPath  string
	httpClient  *http.Client
	runtimeType string // "docker" or "podman"; guarded by availabilityMutex
	runtimeName string // detected runtime name; guarded by availabilityMutex
	// Availability caching to prevent repeated expensive checks. Also guards
	// runtimeType/runtimeName, which IsAvailable rewrites from /version.
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
	d.availabilityMutex.RLock()
	defer d.availabilityMutex.RUnlock()
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
		// The version body says which runtime answered; read it from the
		// response already in hand rather than asking again.
		if d.runtimeType == "unknown" || d.runtimeName == "" {
			d.detectRuntimeFromVersion(resp.Body)
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
	// all=true: without it the endpoint lists running containers only, and a
	// container that crashed would vanish instead of reporting as exited.
	req, err := http.NewRequestWithContext(ctx, "GET", "http://runtime/containers/json?all=true", nil)
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
		name := ac.ID
		if len(ac.Names) > 0 {
			name = cleanContainerName(ac.Names[0])
		} else if len(ac.ID) > 12 {
			name = ac.ID[:12]
		}
		health, exitCode := parseStatus(ac.Status)
		if ac.State != "exited" && ac.State != "dead" {
			exitCode = nil
		}
		containers[i] = Container{
			ID:       ac.ID,
			Name:     name,
			Image:    ac.Image,
			ImageID:  normalizeImageID(ac.ImageID),
			Status:   ac.State,
			Labels:   ac.Labels,
			Created:  time.Unix(ac.Created, 0),
			Health:   health,
			ExitCode: exitCode,
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
	ImageID string            `json:"ImageID"`
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
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  uint32 `json:"online_cpus"`
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
	Networks map[string]struct { // absent for host-network containers
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats struct {
		// nil when the runtime could not read block I/O.
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

// convertAPIStats converts Docker/Podman API stats to ContainerStats.
//
// CPU is put on the `docker stats` / `podman stats` scale, 100 = one core:
// system_cpu_usage is host CPU time summed over every CPU, so the plain
// ratio is a share of the whole host and is multiplied by the CPU count
// (online_cpus, or the per-CPU array length on older APIs). The podman CLI
// client reports the same scale, so the series means one thing whichever
// client answered. Without a previous sample, a CPU count, or with counters
// that went backwards (container restarted), utilization is unknown.
func convertAPIStats(containerID string, stats *statsFromAPI) *ContainerStats {
	out := &ContainerStats{ContainerID: containerID}

	cur, pre := stats.CPUStats, stats.PreCPUStats
	cpus := float64(cur.OnlineCPUs)
	if cpus == 0 {
		cpus = float64(len(cur.CPUUsage.PercpuUsage))
	}
	if cpus > 0 && pre.SystemUsage > 0 && cur.SystemUsage > pre.SystemUsage &&
		cur.CPUUsage.TotalUsage >= pre.CPUUsage.TotalUsage {
		cpuDelta := float64(cur.CPUUsage.TotalUsage - pre.CPUUsage.TotalUsage)
		systemDelta := float64(cur.SystemUsage - pre.SystemUsage)
		out.CPUPercent, out.CPUKnown = cpuDelta/systemDelta*cpus*100.0, true
	}

	// A running container always uses some memory; 0 means not reported.
	if stats.MemoryStats.Usage > 0 {
		out.MemoryUsage, out.MemoryKnown = stats.MemoryStats.Usage, true
		out.MemoryLimit = stats.MemoryStats.Limit
	}

	// Calculate network totals
	if stats.Networks != nil {
		out.NetworkKnown = true
		for _, network := range stats.Networks {
			out.NetworkRxBytes += network.RxBytes
			out.NetworkTxBytes += network.TxBytes
		}
	}

	// Calculate disk I/O totals
	if stats.BlkioStats.IoServiceBytesRecursive != nil {
		out.DiskKnown = true
		for _, io := range stats.BlkioStats.IoServiceBytesRecursive {
			switch strings.ToLower(io.Op) {
			case "read":
				out.DiskReadBytes += io.Value
			case "write":
				out.DiskWriteBytes += io.Value
			}
		}
	}

	return out
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

// detectRuntimeFromVersion reads a /version body and records whether Docker
// or Podman is on the other end of the socket.
func (d *DockerCompatibleClient) detectRuntimeFromVersion(body io.Reader) {
	var versionInfo struct {
		Components []struct {
			Name string `json:"Name"`
		} `json:"Components"`
		Platform struct {
			Name string `json:"Name"`
		} `json:"Platform"`
	}
	if err := json.NewDecoder(body).Decode(&versionInfo); err != nil {
		return
	}

	isPodman := strings.Contains(strings.ToLower(versionInfo.Platform.Name), "podman")
	for _, component := range versionInfo.Components {
		if strings.Contains(strings.ToLower(component.Name), "podman") {
			isPodman = true
		}
	}
	if isPodman {
		d.runtimeType, d.runtimeName = "podman", "podman"
	} else {
		d.runtimeType, d.runtimeName = "docker", "docker"
	}
}
