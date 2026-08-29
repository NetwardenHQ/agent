// Copyright 2024-2025 Netwarden
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config provides simplified configuration for the Netwarden agent.
package config

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultServerURL is the SaaS endpoint used when no server_url is configured.
const DefaultServerURL = "https://api.netwarden.com"

// Config represents the agent configuration.
type Config struct {
	// Core settings (required)
	TenantID string
	APIKey   string

	// Server URL for self-hosted deployments (default: https://api.netwarden.com)
	ServerURL string

	// TLS configuration for self-hosted deployments with self-signed certificates
	TLSSkipVerify bool   // Skip TLS certificate verification (insecure, for self-signed certs)
	TLSCACert     string // Path to custom CA certificate file (PEM format)

	// Optional hostname override
	Hostname string

	// Logging
	LogLevel string
	LogFile  string

	// Buffer configuration
	Buffer BufferConfig

	// Collector flags
	Collectors CollectorToggles

	// Network configuration
	Network NetworkConfig

	// Container configuration
	Container ContainerConfig

	// VM configuration
	VM VMConfig

	// Database configuration
	Database DatabaseConfig

	// Process monitoring configuration
	Process ProcessConfig
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	// Check required fields
	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate tenant ID format (should be 10 characters)
	if len(c.TenantID) != 10 {
		return fmt.Errorf("tenant_id must be exactly 10 characters, got %d", len(c.TenantID))
	}

	if c.APIKey == "" {
		return fmt.Errorf("api_key is required")
	}

	// Validate API key format (should start with nw_sk_)
	if !strings.HasPrefix(c.APIKey, "nw_sk_") {
		return fmt.Errorf("api_key must start with 'nw_sk_'")
	}

	// Validate server URL
	if c.ServerURL != "" && !strings.HasPrefix(c.ServerURL, "http://") && !strings.HasPrefix(c.ServerURL, "https://") {
		return fmt.Errorf("server_url must start with http:// or https://")
	}

	// Validate TLS CA cert file exists if specified
	if c.TLSCACert != "" {
		if _, err := os.Stat(c.TLSCACert); os.IsNotExist(err) {
			return fmt.Errorf("tls_ca_cert file not found: %s", c.TLSCACert)
		}
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if c.LogLevel != "" && !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log_level: %s (must be debug, info, warn, or error)", c.LogLevel)
	}

	// Validate buffer configuration
	if c.Buffer.MaxSize < 0 {
		return fmt.Errorf("buffer max_size cannot be negative")
	}

	// Validate database configuration if enabled
	if c.Database.EnableDatabaseMonitoring {
		if len(c.Database.DatabaseConnections) == 0 {
			return fmt.Errorf("database monitoring enabled but no connections configured")
		}

		for i, conn := range c.Database.DatabaseConnections {
			if conn.DSN == "" {
				return fmt.Errorf("database connection %d: DSN is required", i)
			}
			if conn.Type != "postgresql" && conn.Type != "mysql" {
				return fmt.Errorf("database connection %d: type must be 'postgresql' or 'mysql', got '%s'", i, conn.Type)
			}
		}
	}

	// Validate VM configuration if enabled
	if c.VM.EnableVMs {
		if c.VM.VMHypervisor == "" {
			c.VM.VMHypervisor = "auto" // Default to auto-detection
		}

		// Validate Proxmox settings if using Proxmox
		if strings.Contains(c.VM.VMHypervisor, "proxmox") || c.VM.ProxmoxAPI != "" {
			if c.VM.ProxmoxAPI == "" {
				return fmt.Errorf("VM monitoring with Proxmox requires proxmox_api URL")
			}
			if c.VM.ProxmoxUsername == "" && c.VM.ProxmoxTokenID == "" {
				return fmt.Errorf("VM monitoring with Proxmox requires either username/password or token authentication")
			}
		}

		// Validate parallel stats setting
		if c.VM.VMParallelStats < 0 {
			return fmt.Errorf("VM parallel_stats cannot be negative")
		}
		if c.VM.VMParallelStats > 100 {
			return fmt.Errorf("VM parallel_stats cannot exceed 100")
		}
	}

	// Validate container configuration if enabled
	if c.Container.EnableContainers {
		if c.Container.ContainerRuntime == "" {
			c.Container.ContainerRuntime = "auto" // Default to auto-detection
		}

		validRuntimes := map[string]bool{
			"auto":       true,
			"docker":     true,
			"podman":     true,
			"containerd": true,
		}
		if !validRuntimes[c.Container.ContainerRuntime] {
			return fmt.Errorf("invalid container_runtime: %s", c.Container.ContainerRuntime)
		}

		if c.Container.StatsInterval != 0 && c.Container.StatsInterval < 5*time.Second {
			return fmt.Errorf("container stats_interval must be at least 5 seconds")
		}
	}

	// Validate process configuration if enabled
	if c.Process.EnableProcessMonitoring {
		if c.Process.ConfigEndpoint != "" && !strings.HasPrefix(c.Process.ConfigEndpoint, "/") {
			return fmt.Errorf("process config_endpoint must start with /")
		}
	}

	return nil
}

// BufferConfig for metric buffering
type BufferConfig struct {
	MaxSize int
}

// CollectorToggles for enabling/disabling collectors
type CollectorToggles struct {
	CPU       bool
	Memory    bool
	System    bool
	Disk      bool
	Network   bool
	Container bool
	VM        bool

	// Security-posture collectors. These read materially more sensitive
	// sources than the resource collectors — authentication logs, the sshd
	// configuration, the listening socket table, the package database — so
	// operators need to be able to switch each one off independently.
	// Default on; set `enable_security_auth: false` (etc.) to disable.
	SecurityAuth      bool
	SecuritySSHConfig bool
	SecurityPorts     bool
	SecurityPackages  bool

	// CIS benchmark evaluation. Gated twice over: this toggle, and the
	// presence of a profile defined in the UI. Both must be on.
	CIS bool
}

// NetworkConfig provides configuration for network monitoring
type NetworkConfig struct {
	EnableNetwork       bool
	MonitoredInterfaces []string // Interface names to monitor (empty = auto-detect)
	ExcludeInterfaces   []string // Additional interface patterns to exclude
}

// ContainerConfig provides configuration for container monitoring
type ContainerConfig struct {
	EnableContainers bool
	ContainerRuntime string        // auto, docker, podman, containerd
	ContainerSocket  string        // custom socket path
	ContainerInclude []string      // include patterns
	ContainerExclude []string      // exclude patterns
	StatsInterval    time.Duration // interval for collecting detailed stats
}

// VMConfig provides configuration for VM monitoring
type VMConfig struct {
	EnableVMs     bool
	VMHypervisor  string        // auto, proxmox, libvirt, kvm, xen, qemu
	VMInclude     []string      // VM name patterns to include
	VMExclude     []string      // VM name patterns to exclude
	StatsInterval time.Duration // How often to collect detailed stats

	// Libvirt configuration
	LibvirtURI    string // libvirt connection URI
	LibvirtSocket string // custom socket path

	// Proxmox configuration
	ProxmoxAPI           string // Proxmox API URL (https://host:8006)
	ProxmoxUsername      string // username@realm
	ProxmoxPassword      string // password (for ticket auth)
	ProxmoxTokenID       string // token ID (for API token auth)
	ProxmoxTokenSecret   string // token secret
	ProxmoxNode          string // specific node name (empty = all nodes)
	ProxmoxSkipTLSVerify bool   // skip TLS verification

	// Advanced settings
	VMTimeout       time.Duration // timeout for hypervisor operations
	VMCacheTimeout  time.Duration // how long to cache VM list
	VMParallelStats int           // how many VMs to query stats in parallel
}

// SystemConfig for system collector
type SystemConfig struct {
	Enabled       bool
	CollectUptime bool
}

// DatabaseConnection represents a single database connection
type DatabaseConnection struct {
	Type string // "mysql" or "postgresql"
	DSN  string // Data Source Name
}

// DatabaseConfig for MySQL and PostgreSQL monitoring
type DatabaseConfig struct {
	// General database monitoring
	EnableDatabaseMonitoring bool
	DatabaseConnections      []DatabaseConnection

	// MySQL configuration
	EnableMySQL   bool
	MySQLSocket   string // Auto-detected if empty
	MySQLHost     string // Default: localhost:3306
	MySQLUser     string // Optional service account
	MySQLPassword string // Optional service account

	// PostgreSQL configuration
	EnablePostgreSQL   bool
	PostgreSQLSocket   string // Auto-detected if empty
	PostgreSQLHost     string // Default: localhost:5432
	PostgreSQLUser     string // Optional service account
	PostgreSQLPassword string // Optional service account
	PostgreSQLDatabase string // Default: postgres
}

// ProcessConfig for process monitoring
type ProcessConfig struct {
	EnableProcessMonitoring bool
	ConfigFetchInterval     time.Duration // Default: 5 minutes
	ConfigEndpoint          string        // Default: /agent-config/processes
}

// LoadConfig loads configuration from a simple key-value file.
func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// The config file holds the agent API key (nw_sk_*) and, where those
	// collectors are configured, Proxmox / MySQL / PostgreSQL passwords in
	// cleartext. Warn loudly if any of that is readable beyond its owner.
	// Non-fatal by design: refusing to start would take monitoring down on
	// an already-deployed fleet, and a running agent that complains every
	// boot is more useful than one that silently accepts a leaked key.
	checkConfigPermissions(file, filename)

	// Create config with basic structure
	// Set collector defaults BEFORE parsing so config file values take precedence
	config := &Config{}
	config.Collectors.CPU = true
	config.Collectors.Memory = true
	config.Collectors.System = true
	config.Collectors.Disk = true
	config.Collectors.Network = true
	config.Collectors.Container = true
	config.Collectors.VM = true
	config.Collectors.SecurityAuth = true
	config.Collectors.SecuritySSHConfig = true
	config.Collectors.SecurityPorts = true
	config.Collectors.SecurityPackages = true
	config.Collectors.CIS = true

	// Parse key-value pairs
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split key-value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "tenant_id", "customer_id":
			config.TenantID = value
		case "api_key":
			config.APIKey = value
		case "server_url", "server":
			config.ServerURL = strings.TrimRight(value, "/")
		case "tls_skip_verify":
			config.TLSSkipVerify = value == "true" || value == "yes" || value == "1"
		case "tls_ca_cert":
			config.TLSCACert = value
		case "hostname":
			config.Hostname = value
		case "log_level":
			config.LogLevel = value
		case "logfile", "log_file":
			config.LogFile = value
		case "enable_cis":
			config.Collectors.CIS = isTruthy(value)
		case "enable_security_auth":
			config.Collectors.SecurityAuth = isTruthy(value)
		case "enable_security_sshconfig":
			config.Collectors.SecuritySSHConfig = isTruthy(value)
		case "enable_security_ports":
			config.Collectors.SecurityPorts = isTruthy(value)
		case "enable_security_packages":
			config.Collectors.SecurityPackages = isTruthy(value)
		case "enable_security":
			// Master switch: turns every security-posture collector on or
			// off in one line. Individual enable_security_* keys still
			// apply, so ordering in the file decides — last write wins,
			// matching how the rest of this parser behaves.
			on := isTruthy(value)
			config.Collectors.SecurityAuth = on
			config.Collectors.SecuritySSHConfig = on
			config.Collectors.SecurityPorts = on
			config.Collectors.SecurityPackages = on
		case "enable_cpu":
			config.Collectors.CPU = value == "true" || value == "yes" || value == "1"
		case "enable_memory":
			config.Collectors.Memory = value == "true" || value == "yes" || value == "1"
		case "enable_system":
			config.Collectors.System = value == "true" || value == "yes" || value == "1"
		case "enable_disk":
			config.Collectors.Disk = value == "true" || value == "yes" || value == "1"
		case "enable_network":
			config.Collectors.Network = value == "true" || value == "yes" || value == "1"
			config.Network.EnableNetwork = config.Collectors.Network
		case "network_interfaces":
			// Parse comma-separated interface names
			if value != "" {
				config.Network.MonitoredInterfaces = strings.Split(value, ",")
				for i := range config.Network.MonitoredInterfaces {
					config.Network.MonitoredInterfaces[i] = strings.TrimSpace(config.Network.MonitoredInterfaces[i])
				}
			}
		case "network_exclude":
			// Parse comma-separated exclusion patterns
			if value != "" {
				config.Network.ExcludeInterfaces = strings.Split(value, ",")
				for i := range config.Network.ExcludeInterfaces {
					config.Network.ExcludeInterfaces[i] = strings.TrimSpace(config.Network.ExcludeInterfaces[i])
				}
			}
		case "enable_containers", "enable_container", "enable_docker":
			config.Collectors.Container = value == "true" || value == "yes" || value == "1"
			config.Container.EnableContainers = config.Collectors.Container
		case "container_runtime":
			config.Container.ContainerRuntime = value
		case "container_socket":
			config.Container.ContainerSocket = value
		case "container_stats_interval":
			// Parse as integer seconds
			if seconds, err := strconv.Atoi(value); err == nil {
				config.Container.StatsInterval = time.Duration(seconds) * time.Second
			}
		case "enable_vms", "enable_vm":
			config.Collectors.VM = value == "true" || value == "yes" || value == "1"
			config.VM.EnableVMs = config.Collectors.VM
		case "vm_hypervisor":
			config.VM.VMHypervisor = value
		case "vm_stats_interval":
			// Parse as integer seconds
			if seconds, err := strconv.Atoi(value); err == nil {
				config.VM.StatsInterval = time.Duration(seconds) * time.Second
			}
		case "libvirt_uri":
			config.VM.LibvirtURI = value
		case "libvirt_socket":
			config.VM.LibvirtSocket = value
		case "proxmox_api":
			config.VM.ProxmoxAPI = value
		case "proxmox_username":
			config.VM.ProxmoxUsername = value
		case "proxmox_password":
			config.VM.ProxmoxPassword = value
		case "proxmox_token_id":
			config.VM.ProxmoxTokenID = value
		case "proxmox_token_secret":
			config.VM.ProxmoxTokenSecret = value
		case "proxmox_node":
			config.VM.ProxmoxNode = value
		case "proxmox_skip_tls_verify":
			config.VM.ProxmoxSkipTLSVerify = value == "true" || value == "yes" || value == "1"
		case "enable_mysql":
			config.Database.EnableMySQL = value == "true" || value == "yes" || value == "1"
		case "mysql_socket":
			config.Database.MySQLSocket = value
		case "mysql_host":
			config.Database.MySQLHost = value
		case "mysql_user":
			config.Database.MySQLUser = value
		case "mysql_password":
			config.Database.MySQLPassword = value
		case "enable_postgresql":
			config.Database.EnablePostgreSQL = value == "true" || value == "yes" || value == "1"
		case "postgresql_socket":
			config.Database.PostgreSQLSocket = value
		case "postgresql_host":
			config.Database.PostgreSQLHost = value
		case "postgresql_user":
			config.Database.PostgreSQLUser = value
		case "postgresql_password":
			config.Database.PostgreSQLPassword = value
		case "postgresql_database":
			config.Database.PostgreSQLDatabase = value
		case "enable_process_monitoring":
			config.Process.EnableProcessMonitoring = value == "true" || value == "yes" || value == "1"
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Validate required fields
	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}

	// Set default values for unset fields
	if config.ServerURL == "" {
		config.ServerURL = DefaultServerURL
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	if config.Buffer.MaxSize == 0 {
		config.Buffer.MaxSize = 100
	}

	// Sync sub-config flags with collector toggles (after parsing, so user values are respected)
	config.Network.EnableNetwork = config.Collectors.Network

	// Container configuration defaults
	config.Container.EnableContainers = config.Collectors.Container
	if config.Container.ContainerRuntime == "" {
		config.Container.ContainerRuntime = "auto"
	}
	if config.Container.StatsInterval == 0 {
		config.Container.StatsInterval = 120 * time.Second
	}

	// VM configuration defaults
	config.VM.EnableVMs = config.Collectors.VM
	if config.VM.VMHypervisor == "" {
		config.VM.VMHypervisor = "auto"
	}
	if config.VM.StatsInterval == 0 {
		config.VM.StatsInterval = 120 * time.Second
	}
	if config.VM.VMTimeout == 0 {
		config.VM.VMTimeout = 30 * time.Second
	}
	if config.VM.VMCacheTimeout == 0 {
		config.VM.VMCacheTimeout = 300 * time.Second // 5 minutes
	}
	if config.VM.VMParallelStats == 0 {
		config.VM.VMParallelStats = 5
	}

	// Updates collector removed (security risk)

	// Process monitoring defaults (disabled by default for security)
	// Users must explicitly enable with enable_process_monitoring: true
	// config.Process.EnableProcessMonitoring is false by default (zero value)
	if config.Process.ConfigFetchInterval == 0 {
		config.Process.ConfigFetchInterval = 300 * time.Second // 5 minutes
	}
	if config.Process.ConfigEndpoint == "" {
		config.Process.ConfigEndpoint = "/agent/processes"
	}

	// Validate the configuration before returning
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// CreateConfigFile creates a minimal example configuration file.
func CreateConfigFile(filename string) error {
	content := `# Netwarden Agent Configuration
# Simple key-value configuration file

# Required: Your tenant/customer ID
tenant_id: CHANGE_ME

# Required: Your API key
api_key: nw_sk_CHANGE_ME

# Optional: Server URL for self-hosted deployments (default: https://api.netwarden.com)
# server_url: http://your-server:3000

# Optional: Custom hostname (overrides system hostname)
# hostname: my-server

# Optional: Log level (debug, info, warn, error) (default: info)
log_level: info

# Optional: Log file path (default: .\netwarden.log on Windows, /var/log/netwarden.log on Linux)
# logfile: /path/to/custom/logfile.log

# Optional: Enable/disable collectors (all enabled by default except mysql/postgresql)
# enable_cpu: true
# enable_memory: true
# enable_system: true
# enable_disk: true
# enable_network: true
# enable_containers: true
# enable_vms: true
# enable_process_monitoring: true

# Network monitoring options
# network_interfaces: eth0,eth1  # Specific interfaces to monitor (empty = auto-detect)
# network_exclude: wg*,tun*      # Additional patterns to exclude

# Container monitoring options
# container_runtime: auto
# container_socket: /var/run/docker.sock
# container_stats_interval: 120

# VM monitoring options
# vm_hypervisor: auto
# vm_stats_interval: 120
#
# Libvirt configuration (for KVM, Xen, QEMU)
# libvirt_uri: qemu:///system
# libvirt_socket: /var/run/libvirt/libvirt-sock
#
# Proxmox configuration
# proxmox_api: https://proxmox.example.com:8006
# proxmox_username: monitoring@pve
# proxmox_password: your_password
# proxmox_token_id: monitoring@pve!token
# proxmox_token_secret: your_token_secret
# proxmox_node: node-name
# proxmox_skip_tls_verify: false
#
# Database monitoring (disabled by default - explicitly enable if needed)
# Uses TCP connections by default (localhost:3306 / localhost:5432)
# Socket connections available if you specify a socket path
#
# enable_mysql: false
# mysql_user: svc_netwarden
# mysql_password: your_password
# mysql_host: localhost:3306        # Optional: defaults to localhost:3306
# mysql_socket: /var/run/mysqld/mysqld.sock  # Optional: only if you want socket instead of TCP
#
# enable_postgresql: false
# postgresql_user: svc_netwarden
# postgresql_password: your_password
# postgresql_database: postgres     # Optional: defaults to postgres
# postgresql_host: localhost:5432   # Optional: defaults to localhost:5432
# postgresql_socket: /var/run/postgresql  # Optional: only if you want socket instead of TCP
#
# Process monitoring (enabled by default)
# enable_process_monitoring: true
`

	return os.WriteFile(filename, []byte(content), 0600)
}

// insecureConfigModeMask matches any group or world permission bit. A
// credential file should be 0600 (or 0400); anything looser exposes the API
// key to every local account.
const insecureConfigModeMask = 0o077

// checkConfigPermissions warns when the config file is readable or writable
// by anyone other than its owner. It inspects the already-open handle so the
// check cannot race against a file swapped between open and stat.
//
// Windows is skipped: Unix mode bits are synthesized by the Go runtime there
// and do not reflect the real ACL, so the check would be noise.
func checkConfigPermissions(file *os.File, filename string) {
	if runtime.GOOS == "windows" {
		return
	}

	info, err := file.Stat()
	if err != nil {
		slog.Debug("could not stat config file for permission check",
			"path", filename, "error", err)
		return
	}

	mode := info.Mode().Perm()
	if mode&insecureConfigModeMask == 0 {
		return
	}

	slog.Warn("config file has overly permissive permissions",
		"path", filename,
		"mode", fmt.Sprintf("%#o", mode),
		"risk", "contains the agent API key and any configured database/hypervisor passwords in cleartext",
		"fix", fmt.Sprintf("chmod 600 %s", filename))
}

// isTruthy interprets a config file boolean. Mirrors the inline comparison
// used by the older enable_* keys ("true"/"yes"/"1"), with case-insensitive
// matching so `enable_security: FALSE` behaves as written rather than
// silently reading as true.
func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "1", "on":
		return true
	}
	return false
}
