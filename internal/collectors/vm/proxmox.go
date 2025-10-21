//go:build linux
// +build linux

package vm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"netwarden/internal/config"
)

// ProxmoxClient implements HypervisorClient for Proxmox VE.
type ProxmoxClient struct {
	config     config.VMConfig
	logger     *slog.Logger
	httpClient *http.Client
	baseURL    string
	authHeader string
	authMutex  sync.RWMutex
	authExpiry time.Time
}

// ProxmoxVM represents a VM from Proxmox API.
type ProxmoxVM struct {
	VMID     int     `json:"vmid"`
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	Node     string  `json:"node"`
	Type     string  `json:"type"`
	Template int     `json:"template,omitempty"`
	CPU      float64 `json:"cpu,omitempty"`
	MaxCPU   int     `json:"maxcpu,omitempty"`
	MaxMem   int64   `json:"maxmem,omitempty"`
	MaxDisk  int64   `json:"maxdisk,omitempty"`
	Uptime   int64   `json:"uptime,omitempty"`
}

// ProxmoxVMConfig represents detailed VM configuration.
type ProxmoxVMConfig struct {
	CPU    int    `json:"cpu"`
	Memory int64  `json:"memory"`
	OSType string `json:"ostype"`
	Arch   string `json:"arch"`
}

// ProxmoxVMStats represents VM statistics from Proxmox.
type ProxmoxVMStats struct {
	CPU       float64 `json:"cpu"`
	CPUTime   int64   `json:"cputime"`
	Mem       int64   `json:"mem"`
	MaxMem    int64   `json:"maxmem"`
	NetIn     int64   `json:"netin"`
	NetOut    int64   `json:"netout"`
	DiskRead  int64   `json:"diskread"`
	DiskWrite int64   `json:"diskwrite"`
	Uptime    int64   `json:"uptime"`
}

// ProxmoxAPIResponse represents the standard Proxmox API response format.
type ProxmoxAPIResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors interface{}     `json:"errors,omitempty"`
}

// NewProxmoxClient creates a new Proxmox hypervisor client.
func NewProxmoxClient(config config.VMConfig, logger *slog.Logger) *ProxmoxClient {
	// Create HTTP client with optional TLS skip
	transport := &http.Transport{}
	if config.ProxmoxSkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.VMTimeout,
	}

	return &ProxmoxClient{
		config:     config,
		logger:     logger,
		httpClient: httpClient,
		baseURL:    strings.TrimSuffix(config.ProxmoxAPI, "/") + "/api2/json",
	}
}

// Name returns the hypervisor name.
func (p *ProxmoxClient) Name() string {
	return "proxmox"
}

// IsAvailable checks if Proxmox API is accessible.
func (p *ProxmoxClient) IsAvailable() bool {
	if p.config.ProxmoxAPI == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to get version endpoint (doesn't require auth)
	resp, err := p.makeRequest(ctx, "GET", "/version", nil, false)
	if err != nil {
		p.logger.Debug("proxmox API not available", "error", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// authenticate handles Proxmox authentication using either API tokens or tickets.
func (p *ProxmoxClient) authenticate(ctx context.Context) error {
	p.authMutex.Lock()
	defer p.authMutex.Unlock()

	// Check if we have a valid token-based auth
	if p.config.ProxmoxTokenID != "" && p.config.ProxmoxTokenSecret != "" {
		p.authHeader = fmt.Sprintf("PVEAPIToken=%s=%s", p.config.ProxmoxTokenID, p.config.ProxmoxTokenSecret)
		p.authExpiry = time.Now().Add(24 * time.Hour) // API tokens don't expire
		return nil
	}

	// Use ticket-based authentication
	if p.config.ProxmoxUsername != "" && p.config.ProxmoxPassword != "" {
		return p.authenticateWithTicket(ctx)
	}

	return fmt.Errorf("no valid authentication method configured")
}

// authenticateWithTicket authenticates using username/password to get a ticket.
func (p *ProxmoxClient) authenticateWithTicket(ctx context.Context) error {
	authData := url.Values{
		"username": {p.config.ProxmoxUsername},
		"password": {p.config.ProxmoxPassword},
	}

	resp, err := p.makeRequest(ctx, "POST", "/access/ticket", strings.NewReader(authData.Encode()), false)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: status %d", resp.StatusCode)
	}

	var apiResp ProxmoxAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode authentication response: %w", err)
	}

	var authResult struct {
		Ticket string `json:"ticket"`
		Token  string `json:"CSRFPreventionToken"`
	}

	if err := json.Unmarshal(apiResp.Data, &authResult); err != nil {
		return fmt.Errorf("failed to parse authentication data: %w", err)
	}

	p.authHeader = fmt.Sprintf("PVEAuthCookie=%s", authResult.Ticket)
	p.authExpiry = time.Now().Add(2 * time.Hour) // Tickets typically expire after 2 hours

	return nil
}

// makeRequest creates and executes HTTP requests to the Proxmox API.
func (p *ProxmoxClient) makeRequest(ctx context.Context, method, path string, body io.Reader, needsAuth bool) (*http.Response, error) {
	// Authenticate if needed
	if needsAuth {
		p.authMutex.RLock()
		authValid := p.authHeader != "" && time.Now().Before(p.authExpiry)
		p.authMutex.RUnlock()

		if !authValid {
			if err := p.authenticate(ctx); err != nil {
				return nil, fmt.Errorf("authentication failed: %w", err)
			}
		}
	}

	url := p.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	if needsAuth && p.authHeader != "" {
		if strings.HasPrefix(p.authHeader, "PVEAPIToken=") {
			req.Header.Set("Authorization", p.authHeader)
		} else {
			req.Header.Set("Cookie", p.authHeader)
		}
	}

	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return p.httpClient.Do(req)
}

// ListVMs returns all VMs from Proxmox cluster.
func (p *ProxmoxClient) ListVMs(ctx context.Context) ([]VM, error) {
	// Get cluster resources to list all VMs across nodes
	resp, err := p.makeRequest(ctx, "GET", "/cluster/resources?type=vm", nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to list VMs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var apiResp ProxmoxAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var proxmoxVMs []ProxmoxVM
	if err := json.Unmarshal(apiResp.Data, &proxmoxVMs); err != nil {
		return nil, fmt.Errorf("failed to parse VM data: %w", err)
	}

	vms := make([]VM, 0, len(proxmoxVMs))

	for _, pvm := range proxmoxVMs {
		// Skip templates
		if pvm.Template == 1 {
			continue
		}

		// Filter by node if specified
		if p.config.ProxmoxNode != "" && pvm.Node != p.config.ProxmoxNode {
			continue
		}

		vm := VM{
			ID:         fmt.Sprintf("%d", pvm.VMID),
			Name:       pvm.Name,
			Hypervisor: "proxmox",
			Node:       pvm.Node,
			VMID:       pvm.VMID,
			Status:     pvm.Status,
			OSType:     "", // Will be filled from config if needed
			CPUCount:   pvm.MaxCPU,
			MemoryMB:   pvm.MaxMem / (1024 * 1024),         // Convert bytes to MB
			DiskGB:     pvm.MaxDisk / (1024 * 1024 * 1024), // Convert bytes to GB
			Labels:     make(map[string]string),
			Created:    time.Time{}, // Not available in cluster resources
		}

		// Add Proxmox-specific labels
		vm.Labels["node"] = pvm.Node
		vm.Labels["vmid"] = fmt.Sprintf("%d", pvm.VMID)
		vm.Labels["type"] = pvm.Type

		vms = append(vms, vm)
	}

	p.logger.Debug("proxmox: listed VMs", "count", len(vms))
	return vms, nil
}

// GetVMStats retrieves detailed statistics for a specific VM.
func (p *ProxmoxClient) GetVMStats(ctx context.Context, vmID string) (*VMStats, error) {
	// Find the VM to get its node
	vms, err := p.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to find VM node: %w", err)
	}

	var node string
	var vmidInt int
	for _, vm := range vms {
		if vm.ID == vmID {
			node = vm.Node
			vmidInt = vm.VMID
			break
		}
	}

	if node == "" {
		return nil, fmt.Errorf("VM not found: %s", vmID)
	}

	// Get VM statistics from the specific node
	path := fmt.Sprintf("/nodes/%s/qemu/%d/status/current", node, vmidInt)
	resp, err := p.makeRequest(ctx, "GET", path, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stats request failed with status %d", resp.StatusCode)
	}

	var apiResp ProxmoxAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}

	var proxmoxStats ProxmoxVMStats
	if err := json.Unmarshal(apiResp.Data, &proxmoxStats); err != nil {
		return nil, fmt.Errorf("failed to parse stats data: %w", err)
	}

	// Convert Proxmox stats to our format
	stats := &VMStats{
		VMID:              vmID,
		CPUUsagePercent:   proxmoxStats.CPU * 100,     // Proxmox returns 0.0-1.0, we want 0-100
		CPUTime:           proxmoxStats.CPUTime * 1e9, // Convert seconds to nanoseconds
		MemoryUsageMB:     proxmoxStats.Mem / (1024 * 1024),
		MemoryAvailableMB: (proxmoxStats.MaxMem - proxmoxStats.Mem) / (1024 * 1024),
		NetworkRxBytes:    proxmoxStats.NetIn,
		NetworkTxBytes:    proxmoxStats.NetOut,
		DiskReadBytes:     proxmoxStats.DiskRead,
		DiskWriteBytes:    proxmoxStats.DiskWrite,
		Uptime:            proxmoxStats.Uptime,
	}

	// Calculate memory usage percentage
	if proxmoxStats.MaxMem > 0 {
		stats.MemoryUsagePercent = float64(proxmoxStats.Mem) / float64(proxmoxStats.MaxMem) * 100.0
	}

	return stats, nil
}

// Close closes any connections to Proxmox.
func (p *ProxmoxClient) Close() error {
	// HTTP client doesn't need explicit closing
	return nil
}
