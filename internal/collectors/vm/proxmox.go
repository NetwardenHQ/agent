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

	"github.com/NetwardenHQ/agent/internal/config"
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

	// Reachability is checked on every cycle (Enabled, then Collect) and
	// costs a network round trip, so the answer is cached.
	availMu      sync.Mutex
	available    bool
	availChecked time.Time
}

// availabilityTTL is how long a reachability verdict is reused.
const availabilityTTL = time.Minute

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

// ProxmoxVMStats is the status/current answer for a guest. FreeMem is only
// present when the guest runs the QEMU agent; MaxDisk/Disk are the
// configured and (for containers) used disk sizes.
type ProxmoxVMStats struct {
	CPU       float64 `json:"cpu"`
	CPUs      float64 `json:"cpus"`
	CPUTime   int64   `json:"cputime"`
	Mem       int64   `json:"mem"`
	MaxMem    int64   `json:"maxmem"`
	FreeMem   int64   `json:"freemem"`
	MaxDisk   int64   `json:"maxdisk"`
	Disk      int64   `json:"disk"`
	NetIn     int64   `json:"netin"`
	NetOut    int64   `json:"netout"`
	DiskRead  int64   `json:"diskread"`
	DiskWrite int64   `json:"diskwrite"`
	Uptime    int64   `json:"uptime"`
}

// ProxmoxAPIResponse represents the standard Proxmox API response format.
// Errors is a free-form object whose shape varies by endpoint; it is kept
// raw and only ever logged.
type ProxmoxAPIResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors json.RawMessage `json:"errors,omitempty"`
}

// NewProxmoxClient creates a new Proxmox hypervisor client.
func NewProxmoxClient(config config.VMConfig, logger *slog.Logger) *ProxmoxClient {
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

// IsAvailable reports whether the Proxmox API answers, re-checking at most
// once per availabilityTTL.
func (p *ProxmoxClient) IsAvailable() bool {
	if p.config.ProxmoxAPI == "" {
		return false
	}

	p.availMu.Lock()
	defer p.availMu.Unlock()
	if time.Since(p.availChecked) < availabilityTTL {
		return p.available
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// PVE answers 401 to an unauthenticated /version (only /access/ticket
	// is open), so the probe carries the credentials: it then tests
	// reachability and authentication together, which is what Collect needs.
	resp, err := p.makeRequest(ctx, "GET", "/version", nil, true)
	if err != nil {
		p.logger.Debug("proxmox API not available", "error", err)
		p.available, p.availChecked = false, time.Now()
		return false
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		p.logger.Warn("proxmox API rejected the configured credentials",
			"status", resp.StatusCode, "api", p.config.ProxmoxAPI)
	}
	p.available, p.availChecked = resp.StatusCode == http.StatusOK, time.Now()
	return p.available
}

// authenticate handles Proxmox authentication using either API tokens or tickets.
func (p *ProxmoxClient) authenticate(ctx context.Context) error {
	p.authMutex.Lock()
	defer p.authMutex.Unlock()

	if p.config.ProxmoxTokenID != "" && p.config.ProxmoxTokenSecret != "" {
		p.authHeader = fmt.Sprintf("PVEAPIToken=%s=%s", p.config.ProxmoxTokenID, p.config.ProxmoxTokenSecret)
		p.authExpiry = time.Now().Add(24 * time.Hour) // API tokens don't expire
		return nil
	}

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
	// Authenticate if needed. The header is copied under the lock: another
	// request may be re-authenticating and rewriting it.
	authHeader := ""
	if needsAuth {
		p.authMutex.RLock()
		authValid := p.authHeader != "" && time.Now().Before(p.authExpiry)
		authHeader = p.authHeader
		p.authMutex.RUnlock()

		if !authValid {
			if err := p.authenticate(ctx); err != nil {
				return nil, fmt.Errorf("authentication failed: %w", err)
			}
			p.authMutex.RLock()
			authHeader = p.authHeader
			p.authMutex.RUnlock()
		}
	}

	url := p.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	if authHeader != "" {
		if strings.HasPrefix(authHeader, "PVEAPIToken=") {
			req.Header.Set("Authorization", authHeader)
		} else {
			req.Header.Set("Cookie", authHeader)
		}
	}

	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := p.httpClient.Do(req)
	if err == nil && needsAuth && resp.StatusCode == http.StatusUnauthorized {
		// A ticket can be revoked or expire early; force a fresh login on
		// the next request instead of reusing it until authExpiry.
		p.authMutex.Lock()
		if p.authHeader == authHeader {
			p.authExpiry = time.Time{}
		}
		p.authMutex.Unlock()
	}
	return resp, err
}

// ListVMs returns all VMs from Proxmox cluster.
func (p *ProxmoxClient) ListVMs(ctx context.Context) ([]VM, error) {
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
		if pvm.Template == 1 {
			continue
		}

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
			OSType:     "",
			CPUCount:   pvm.MaxCPU,
			MemoryMB:   pvm.MaxMem / (1024 * 1024),         // Convert bytes to MB
			DiskGB:     pvm.MaxDisk / (1024 * 1024 * 1024), // Convert bytes to GB
			Labels:     make(map[string]string),
			Created:    time.Time{}, // Not available in cluster resources
		}

		vm.Labels["node"] = pvm.Node
		vm.Labels["vmid"] = fmt.Sprintf("%d", pvm.VMID)
		vm.Labels["type"] = pvm.Type

		vms = append(vms, vm)
	}

	p.logger.Debug("proxmox: listed VMs", "count", len(vms))
	return vms, nil
}

// GetVMStats retrieves the current status of one VM from its node. The VM
// from ListVMs already names the node and VMID, so this is a single call.
func (p *ProxmoxClient) GetVMStats(ctx context.Context, vm VM) (*VMStats, error) {
	if vm.Node == "" || vm.VMID == 0 {
		return nil, fmt.Errorf("VM %s has no node/VMID", vm.ID)
	}
	kind := "qemu"
	if vm.Labels["type"] == "lxc" {
		kind = "lxc"
	}
	path := fmt.Sprintf("/nodes/%s/%s/%d/status/current", url.PathEscape(vm.Node), kind, vm.VMID)
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

	// Proxmox reports cpu as a 0–1 fraction of the VM's cores.
	stats := &VMStats{
		VMID:            vm.ID,
		CPUUsagePercent: proxmoxStats.CPU * 100,
		CPUUsageKnown:   true,
		CPUTime:         proxmoxStats.CPUTime * 1e9, // Convert seconds to nanoseconds
		MemoryUsageMB:   proxmoxStats.Mem / (1024 * 1024),
		MemoryKnown:     true,
		NetworkRxBytes:  proxmoxStats.NetIn,
		NetworkTxBytes:  proxmoxStats.NetOut,
		DiskReadBytes:   proxmoxStats.DiskRead,
		DiskWriteBytes:  proxmoxStats.DiskWrite,
		Uptime:          proxmoxStats.Uptime,
	}

	if proxmoxStats.MaxMem > 0 {
		// A guest can sit above maxmem (QEMU overhead, ballooning); that
		// is no headroom, not negative headroom.
		if proxmoxStats.MaxMem > proxmoxStats.Mem {
			stats.MemoryAvailableMB = (proxmoxStats.MaxMem - proxmoxStats.Mem) / (1024 * 1024)
		}
		stats.MemoryUsagePercent = float64(proxmoxStats.Mem) / float64(proxmoxStats.MaxMem) * 100.0
		stats.MemoryLimitKnown = true
	}
	stats.VCPUCurrent = int(proxmoxStats.CPUs)

	// The guest's own view arrives only with the QEMU agent (freemem); an
	// LXC container reports it natively.
	if proxmoxStats.FreeMem > 0 && proxmoxStats.MaxMem >= proxmoxStats.FreeMem {
		used := proxmoxStats.MaxMem - proxmoxStats.FreeMem
		stats.GuestMemoryTotalMB = proxmoxStats.MaxMem / (1024 * 1024)
		stats.GuestMemoryUsedMB = used / (1024 * 1024)
		stats.GuestMemoryUsagePercent = float64(used) / float64(proxmoxStats.MaxMem) * 100
		stats.GuestMemoryKnown = true
	}
	if proxmoxStats.MaxDisk > 0 {
		stats.DiskCapacityBytes = proxmoxStats.MaxDisk
		stats.DiskAllocationBytes = proxmoxStats.Disk
		stats.DiskAllocationKnown = proxmoxStats.Disk > 0 // QEMU reports 0 here; only LXC knows
	}

	return stats, nil
}

// Close closes any connections to Proxmox.
func (p *ProxmoxClient) Close() error {
	return nil
}
