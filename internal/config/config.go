// Copyright 2024-2026 Netwarden
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

// Package config loads and validates the Netwarden agent configuration file.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultServerURL is the SaaS endpoint used when no server_url is configured.
const DefaultServerURL = "https://api.netwarden.com"

// SelfUpdateConfig bounds when and from where the agent may replace itself.
//
// These settings are local and take precedence over the server, so an
// operator can rule out unattended upgrades, use an internal mirror or trust
// their own signing certificate, and have that decision be final.
type SelfUpdateConfig struct {
	// Enabled allows silent self-update. It defaults to true on every
	// platform, but only the Windows build acts on it (see Config.SelfUpdate).
	// When false the agent ignores update hints.
	Enabled bool

	// WindowStartHour/WindowEndHour bound the local hours in which an update
	// may be applied, because applying one restarts the service. Start may be
	// greater than end to span midnight.
	WindowStartHour int
	WindowEndHour   int

	// URLTemplate, when set, replaces whatever download location the server
	// offers, for airgapped sites and internal mirrors. It supports {version},
	// {os} and {arch} placeholders, for example
	//
	//	https://mirror.internal/netwarden/netwarden-{version}-{os}-{arch}-installer.exe
	URLTemplate string

	// Signers replaces the built-in list of acceptable code-signing subjects,
	// for builds signed with a different certificate.
	//
	// The server can never influence this setting: it may say where to
	// download from, never whose signature to accept.
	Signers []string
}

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

	// SelfUpdate controls silent agent upgrades. Windows only: on Linux the
	// packages register a signed apt/yum repo and the systemd unit denies
	// the agent write access to its own binary, so upgrades belong to the
	// package manager.
	SelfUpdate SelfUpdateConfig

	// Collector flags
	Collectors CollectorToggles

	// LangPackageRoots are extra directories to scan for host-installed
	// language packages (node_modules, non-system site-packages). Applies
	// only when Collectors.SecurityLangPackages is set.
	LangPackageRoots []string

	// FIMManifestPath overrides where the FIM baseline is stored (default
	// /var/db/netwarden/fim-manifest on FreeBSD, /var/lib/netwarden/fim-manifest
	// on other Unix systems, %ProgramData%\Netwarden\fim-manifest on
	// Windows). FIMRoots adds watched paths to the compiled default ruleset.
	// Both apply only when Collectors.FIM is set.
	FIMManifestPath string
	FIMRoots        []string

	// SpoolDir is the directory local producers (for example an OPNsense UI
	// plugin) write events and exposure files into for the agent to forward.
	// Empty disables the spool. Default: /var/db/netwarden/spool on FreeBSD,
	// /var/lib/netwarden/spool on Linux, disabled elsewhere unless spool_dir
	// is set. spool_dir: off disables it explicitly.
	SpoolDir string

	// FIMRealtime enables the fsnotify real-time layer. Default true, except
	// on macOS and FreeBSD, where kqueue holds an open descriptor for every
	// file in each watched directory. Applies only when Collectors.FIM is set.
	// Disable with enable_fim_realtime: false on hosts where inotify watch
	// descriptors are scarce.
	FIMRealtime bool

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

	// Warnings are non-fatal problems found while loading, such as an
	// over-permissive or foreign-owned config file. LoadConfig runs before the
	// log file is open, so the caller logs them once logging is set up.
	Warnings []string
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	if len(c.TenantID) != 10 {
		return fmt.Errorf("tenant_id must be exactly 10 characters, got %d", len(c.TenantID))
	}

	if c.APIKey == "" {
		return fmt.Errorf("api_key is required")
	}

	if !strings.HasPrefix(c.APIKey, "nw_sk_") {
		return fmt.Errorf("api_key must start with 'nw_sk_'")
	}

	if c.ServerURL != "" && !strings.HasPrefix(c.ServerURL, "http://") && !strings.HasPrefix(c.ServerURL, "https://") {
		return fmt.Errorf("server_url must start with http:// or https://")
	}

	if c.TLSCACert != "" {
		if _, err := os.Stat(c.TLSCACert); os.IsNotExist(err) {
			return fmt.Errorf("tls_ca_cert file not found: %s", c.TLSCACert)
		}
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if c.LogLevel != "" && !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log_level: %s (must be debug, info, warn, or error)", c.LogLevel)
	}

	if c.VM.EnableVMs {
		if c.VM.VMHypervisor == "" {
			c.VM.VMHypervisor = "auto"
		}

		if strings.Contains(c.VM.VMHypervisor, "proxmox") || c.VM.ProxmoxAPI != "" {
			if c.VM.ProxmoxAPI == "" {
				return fmt.Errorf("VM monitoring with Proxmox requires proxmox_api URL")
			}
			if c.VM.ProxmoxUsername == "" && c.VM.ProxmoxTokenID == "" {
				return fmt.Errorf("VM monitoring with Proxmox requires either username/password or token authentication")
			}
		}

		if c.VM.VMParallelStats < 0 {
			return fmt.Errorf("VM parallel_stats cannot be negative")
		}
		if c.VM.VMParallelStats > 100 {
			return fmt.Errorf("VM parallel_stats cannot exceed 100")
		}
	}

	if c.Container.EnableContainers {
		if c.Container.ContainerRuntime == "" {
			c.Container.ContainerRuntime = "auto"
		}

		validRuntimes := map[string]bool{
			"auto":   true,
			"docker": true,
			"podman": true,
			// Accepted so existing configs keep loading; no containerd
			// client exists, so it collects nothing.
			"containerd": true,
		}
		if !validRuntimes[c.Container.ContainerRuntime] {
			return fmt.Errorf("invalid container_runtime: %s", c.Container.ContainerRuntime)
		}

		if c.Container.StatsInterval != 0 && c.Container.StatsInterval < 5*time.Second {
			return fmt.Errorf("container stats_interval must be at least 5 seconds")
		}
	}

	if c.Process.EnableProcessMonitoring {
		if c.Process.ConfigEndpoint != "" && !strings.HasPrefix(c.Process.ConfigEndpoint, "/") {
			return fmt.Errorf("process config_endpoint must start with /")
		}
	}

	return nil
}

// CollectorToggles switches individual collectors on or off.
type CollectorToggles struct {
	CPU       bool
	Memory    bool
	System    bool
	Disk      bool
	Network   bool
	Container bool
	VM        bool

	// Security-posture collectors. They read more sensitive sources than the
	// resource collectors (authentication logs, the sshd configuration, the
	// listening socket table, the package database), so each can be switched
	// off on its own. Default on; enable_security_auth: false (and so on)
	// disables one.
	SecurityAuth      bool
	SecuritySSHConfig bool
	SecurityPorts     bool
	SecurityPackages  bool

	// OPNsense enables the OPNsense collector (gateways, firmware, pf, IDS,
	// firewall and audit logs, CARP, config changes). It only runs on a host
	// that is an OPNsense firewall; elsewhere it stays inactive.
	OPNsense bool

	// SecurityLangPackages enables discovery of host-installed language
	// packages: pip site-packages (auto-discovered, bounded walk) plus npm
	// node_modules under LangPackageRoots. Default on; Node requires explicit
	// roots.
	SecurityLangPackages bool

	// CIS enables CIS benchmark evaluation. It runs only when this toggle is
	// on and a profile is defined in the UI.
	CIS bool

	// FIM enables file integrity monitoring. Default off: unlike the other
	// collectors it does sustained I/O and keeps a baseline manifest on disk.
	FIM bool

	// K8sJobs, K8sAvailability, K8sResources, K8sCNPG and K8sIngress mirror the
	// capabilities selected when the install manifest was generated, and must
	// match the ClusterRole it granted: a watcher started without its RBAC
	// retries forever and logs a 403 on every backoff.
	//
	// They default to true so a config file written before these keys
	// existed, against a ClusterRole that granted everything, keeps working.
	K8sJobs         bool
	K8sAvailability bool
	K8sResources    bool
	K8sCNPG         bool
	K8sIngress      bool

	// Kubernetes enables cluster monitoring from inside a pod. Default on:
	// the collector activates only when it finds an in-cluster ServiceAccount
	// token, so on an ordinary host it stays inert. Disable with
	// enable_kubernetes: false.
	Kubernetes bool
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
	ContainerRuntime string        // auto, docker, podman
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

// DatabaseConfig for MySQL and PostgreSQL monitoring
type DatabaseConfig struct {
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

	// The file holds the agent API key and any Proxmox, MySQL or PostgreSQL
	// passwords in cleartext. Loose permissions are a warning, not an error:
	// refusing to start would take monitoring down across a deployed fleet.
	warnings := checkConfigPermissions(file, filename)

	// Defaults are set before parsing so values in the file take precedence.
	config := &Config{Warnings: warnings}

	// Self-update is on by default, because a fleet upgraded by hand drifts
	// behind. The download location comes from the server this agent reports
	// to, so a self-hosted install serves its own repository. The default
	// window is the quiet hours, because applying an update restarts the
	// service. Only Windows acts on it; Linux upgrades through the package's
	// apt/yum repository.
	config.SelfUpdate.Enabled = true
	config.SelfUpdate.WindowStartHour = 1
	config.SelfUpdate.WindowEndHour = 5

	switch runtime.GOOS {
	case "freebsd":
		config.SpoolDir = "/var/db/netwarden/spool"
	case "linux":
		config.SpoolDir = "/var/lib/netwarden/spool"
	}

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
	config.Collectors.OPNsense = true
	config.Collectors.SecurityLangPackages = true
	config.FIMRealtime = runtime.GOOS != "darwin" && runtime.GOOS != "freebsd"
	config.Collectors.CIS = true
	config.Collectors.Kubernetes = true
	config.Collectors.K8sJobs = true
	config.Collectors.K8sAvailability = true
	config.Collectors.K8sResources = true
	config.Collectors.K8sCNPG = true
	config.Collectors.K8sIngress = true

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := parseValue(parts[1])

		switch key {
		case "tenant_id", "customer_id":
			config.TenantID = value
		case "api_key":
			config.APIKey = value
		case "server_url", "server":
			config.ServerURL = strings.TrimRight(value, "/")
		case "self_update":
			config.SelfUpdate.Enabled = isTruthy(value)
		case "self_update_window_start":
			if h, err := strconv.Atoi(value); err == nil && h >= 0 && h <= 23 {
				config.SelfUpdate.WindowStartHour = h
			}
		case "self_update_window_end":
			if h, err := strconv.Atoi(value); err == nil && h >= 0 && h <= 23 {
				config.SelfUpdate.WindowEndHour = h
			}
		case "self_update_url":
			config.SelfUpdate.URLTemplate = value
		case "self_update_signers", "self_update_signer":
			config.SelfUpdate.Signers = splitList(value)
		case "tls_skip_verify":
			config.TLSSkipVerify = isTruthy(value)
		case "tls_ca_cert":
			config.TLSCACert = value
		case "hostname":
			config.Hostname = value
		case "log_level":
			config.LogLevel = value
		case "logfile", "log_file":
			config.LogFile = value
		case "enable_security_lang_packages", "enable_language_packages":
			config.Collectors.SecurityLangPackages = isTruthy(value)
		case "language_package_roots", "lang_package_roots":
			for _, r := range strings.Split(value, ",") {
				if r = strings.TrimSpace(r); r != "" {
					config.LangPackageRoots = append(config.LangPackageRoots, r)
				}
			}
		case "enable_cis":
			config.Collectors.CIS = isTruthy(value)
		case "enable_kubernetes", "enable_k8s":
			config.Collectors.Kubernetes = isTruthy(value)
		case "k8s_enable_jobs":
			config.Collectors.K8sJobs = isTruthy(value)
		case "k8s_enable_availability":
			config.Collectors.K8sAvailability = isTruthy(value)
		case "k8s_enable_resources":
			config.Collectors.K8sResources = isTruthy(value)
		case "k8s_enable_cnpg":
			config.Collectors.K8sCNPG = isTruthy(value)
		case "k8s_enable_ingress":
			config.Collectors.K8sIngress = isTruthy(value)
		case "enable_fim", "enable_file_integrity":
			config.Collectors.FIM = isTruthy(value)
		case "enable_fim_realtime":
			config.FIMRealtime = isTruthy(value)
		case "spool_dir":
			v := strings.TrimSpace(value)
			if strings.EqualFold(v, "off") || strings.EqualFold(v, "none") || strings.EqualFold(v, "disabled") {
				v = ""
			}
			config.SpoolDir = v
		case "fim_manifest_path":
			config.FIMManifestPath = strings.TrimSpace(value)
		case "fim_roots", "file_integrity_roots":
			for _, r := range strings.Split(value, ",") {
				if r = strings.TrimSpace(r); r != "" {
					config.FIMRoots = append(config.FIMRoots, r)
				}
			}
		case "enable_security_auth":
			config.Collectors.SecurityAuth = isTruthy(value)
		case "enable_security_sshconfig":
			config.Collectors.SecuritySSHConfig = isTruthy(value)
		case "enable_security_ports":
			config.Collectors.SecurityPorts = isTruthy(value)
		case "enable_opnsense":
			config.Collectors.OPNsense = isTruthy(value)
		case "enable_security_packages":
			config.Collectors.SecurityPackages = isTruthy(value)
		case "enable_security":
			// Master switch for the security-posture collectors. Individual
			// enable_security_* keys still apply; as everywhere in this
			// parser, the last line in the file wins.
			on := isTruthy(value)
			config.Collectors.SecurityAuth = on
			config.Collectors.SecuritySSHConfig = on
			config.Collectors.SecurityPorts = on
			config.Collectors.SecurityPackages = on
		case "enable_cpu":
			config.Collectors.CPU = isTruthy(value)
		case "enable_memory":
			config.Collectors.Memory = isTruthy(value)
		case "enable_system":
			config.Collectors.System = isTruthy(value)
		case "enable_disk":
			config.Collectors.Disk = isTruthy(value)
		case "enable_network":
			config.Collectors.Network = isTruthy(value)
			config.Network.EnableNetwork = config.Collectors.Network
		case "network_interfaces":
			if value != "" {
				config.Network.MonitoredInterfaces = strings.Split(value, ",")
				for i := range config.Network.MonitoredInterfaces {
					config.Network.MonitoredInterfaces[i] = strings.TrimSpace(config.Network.MonitoredInterfaces[i])
				}
			}
		case "network_exclude":
			if value != "" {
				config.Network.ExcludeInterfaces = strings.Split(value, ",")
				for i := range config.Network.ExcludeInterfaces {
					config.Network.ExcludeInterfaces[i] = strings.TrimSpace(config.Network.ExcludeInterfaces[i])
				}
			}
		case "enable_containers", "enable_container", "enable_docker":
			config.Collectors.Container = isTruthy(value)
			config.Container.EnableContainers = config.Collectors.Container
		case "container_runtime":
			config.Container.ContainerRuntime = value
		case "container_socket":
			config.Container.ContainerSocket = value
		case "container_stats_interval":
			if seconds, err := strconv.Atoi(value); err == nil {
				config.Container.StatsInterval = time.Duration(seconds) * time.Second
			}
		case "enable_vms", "enable_vm":
			config.Collectors.VM = isTruthy(value)
			config.VM.EnableVMs = config.Collectors.VM
		case "vm_hypervisor":
			config.VM.VMHypervisor = value
		case "vm_stats_interval":
			if seconds, err := strconv.Atoi(value); err == nil {
				config.VM.StatsInterval = time.Duration(seconds) * time.Second
			}
		case "vm_timeout":
			if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
				config.VM.VMTimeout = time.Duration(seconds) * time.Second
			}
		case "vm_cache_timeout":
			if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
				config.VM.VMCacheTimeout = time.Duration(seconds) * time.Second
			}
		case "vm_parallel_stats":
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				config.VM.VMParallelStats = n
			}
		case "vm_include":
			config.VM.VMInclude = splitList(value)
		case "vm_exclude":
			config.VM.VMExclude = splitList(value)
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
			config.VM.ProxmoxSkipTLSVerify = isTruthy(value)
		case "enable_mysql":
			config.Database.EnableMySQL = isTruthy(value)
		case "mysql_socket":
			config.Database.MySQLSocket = value
		case "mysql_host":
			config.Database.MySQLHost = value
		case "mysql_user":
			config.Database.MySQLUser = value
		case "mysql_password":
			config.Database.MySQLPassword = value
		case "enable_postgresql":
			config.Database.EnablePostgreSQL = isTruthy(value)
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
			config.Process.EnableProcessMonitoring = isTruthy(value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}

	if config.ServerURL == "" {
		config.ServerURL = DefaultServerURL
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	config.Network.EnableNetwork = config.Collectors.Network

	config.Container.EnableContainers = config.Collectors.Container
	if config.Container.ContainerRuntime == "" {
		config.Container.ContainerRuntime = "auto"
	}
	if config.Container.StatsInterval == 0 {
		config.Container.StatsInterval = 120 * time.Second
	}

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
		config.VM.VMCacheTimeout = 300 * time.Second
	}
	if config.VM.VMParallelStats == 0 {
		config.VM.VMParallelStats = 5
	}

	// Process monitoring stays off unless enable_process_monitoring is set.
	if config.Process.ConfigFetchInterval == 0 {
		config.Process.ConfigFetchInterval = 300 * time.Second
	}
	if config.Process.ConfigEndpoint == "" {
		config.Process.ConfigEndpoint = "/agent/processes"
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// CreateConfigFile writes an annotated example configuration file. Every key
// the parser understands is listed, commented out where it is optional.
func CreateConfigFile(filename string) error {
	content := `# Netwarden Agent Configuration
# Format: "key: value", one per line. A line starting with # is a comment, and
# " #" after a value starts a trailing comment. Quote a value that contains " #".
# Booleans accept true/false, yes/no, on/off and 1/0.
# Keep this file mode 0600: it holds credentials.

# Required: your tenant ID (10 characters)
tenant_id: CHANGE_ME

# Required: your agent API key
api_key: nw_sk_CHANGE_ME

# Server URL for self-hosted deployments (default: https://api.netwarden.com)
# server_url: https://netwarden.example.com
# tls_ca_cert: /etc/netwarden/ca.pem      # trust a private CA for server_url
# tls_skip_verify: false                  # insecure; only for self-signed test servers

# Self-update (default: on; applied on Windows only, Linux upgrades through
# apt/yum). The server announces new versions in its replies to the agent.
# self_update: true
# self_update_window_start: 1             # local hour the update window opens
# self_update_window_end: 5               # local hour it closes; an update restarts the service
#
# Download location that replaces the server's URL (airgapped sites, mirrors):
# self_update_url: https://mirror.internal/netwarden-{version}-{os}-{arch}-installer.exe
#
# Code-signing identities to accept, comma separated, replacing the built-in
# list (for builds signed with your own certificate). Each entry is a key pin
# (spki-sha256:<hex>, survives renewal with the same key), a certificate pin
# (sha256:<hex> thumbprint) or an exact certificate CN (weakest).
# self_update_signers: Acme Corp

# Hostname to report (default: the system hostname)
# hostname: my-server

# Logging (level default: info). The log file defaults to
# /var/log/netwarden/netwarden.log on Unix and to the executable's directory
# on Windows.
log_level: info                           # debug|info|warn|error
# log_file: /var/log/netwarden/netwarden.log

# ---------------------------------------------------------------------------
# Resource collectors (all on by default)
# ---------------------------------------------------------------------------
# enable_cpu: true
# enable_memory: true
# enable_system: true
# enable_disk: true
# enable_network: true
# network_interfaces: eth0,eth1   # only these interfaces (default: auto-detect)
# network_exclude: wg*,tun*       # extra interface patterns to ignore

# Containers (Docker, Podman; on by default, inert when no runtime)
# enable_containers: true
# container_runtime: auto         # auto|docker|podman
# container_socket: /var/run/docker.sock
# container_stats_interval: 120   # seconds

# Virtual machines (Linux only; on by default, inert when no hypervisor)
# enable_vms: true
# vm_hypervisor: auto             # auto|proxmox|libvirt|kvm|xen|qemu
# vm_include: prod-*,db-*         # only VMs matching these name globs
# vm_exclude: test-*              # then drop VMs matching these
# vm_timeout: 30                  # seconds per hypervisor operation
# vm_cache_timeout: 300           # seconds to keep the VM list
# vm_parallel_stats: 5            # VMs queried for stats at once
# libvirt_uri: qemu:///system
# libvirt_socket: /var/run/libvirt/libvirt-sock
# proxmox_api: https://proxmox.example.com:8006
# proxmox_username: monitoring@pve
# proxmox_password: secret
# proxmox_token_id: monitoring@pve!token
# proxmox_token_secret: secret
# proxmox_node: node-name
# proxmox_skip_tls_verify: false

# Kubernetes (on by default; active only when running inside a cluster with a
# ServiceAccount). The k8s_enable_* keys must match the RBAC the install
# manifest granted.
# enable_kubernetes: true
# k8s_enable_jobs: true
# k8s_enable_availability: true
# k8s_enable_resources: true
# k8s_enable_cnpg: true
# k8s_enable_ingress: true

# ---------------------------------------------------------------------------
# Databases (off by default; TCP to localhost unless a socket is given)
# ---------------------------------------------------------------------------
# enable_mysql: false
# mysql_user: svc_netwarden
# mysql_password: secret
# mysql_host: localhost:3306
# mysql_socket: /var/run/mysqld/mysqld.sock
#
# enable_postgresql: false
# postgresql_user: svc_netwarden
# postgresql_password: secret
# postgresql_database: postgres
# postgresql_host: localhost:5432
# postgresql_socket: /var/run/postgresql

# Application processes defined in the Netwarden UI (off by default)
# enable_process_monitoring: false

# ---------------------------------------------------------------------------
# Security posture (on by default; each can be switched off on its own, or
# all at once with enable_security: false)
# ---------------------------------------------------------------------------
# enable_security_auth: true          # failed-login counts (journald, auth.log)
# enable_security_sshconfig: true     # sshd_config audit
# enable_opnsense: true               # OPNsense firewalls only: gateways, firmware, pf, IDS, logs, CARP
# enable_security_ports: true         # listening sockets
# enable_security_packages: true      # installed OS packages
# enable_security_lang_packages: true # pip and npm packages installed on the host
# language_package_roots: /srv/app    # extra directories to scan for node_modules
# enable_cis: true                    # CIS benchmark, when a profile is set in the UI

# File integrity monitoring (off by default; it keeps a baseline on disk)
# enable_fim: false
# enable_fim_realtime: true           # real-time layer over the hourly walk (default off on macOS and FreeBSD)
# fim_manifest_path: /var/lib/netwarden/fim-manifest   # FreeBSD: /var/db/netwarden/fim-manifest
# fim_roots: /etc/myapp,/opt/myapp/bin                 # paths added to the default ruleset

# Spool directory for events and exposure files written by local producers,
# such as an OPNsense UI plugin (format: docs/spool.md). It must be owned by
# root and not group- or world-writable. Default: /var/db/netwarden/spool on
# FreeBSD, /var/lib/netwarden/spool on Linux, off elsewhere.
# spool_dir: /var/db/netwarden/spool  # "off" disables it
`

	// O_EXCL: never overwrite an existing config, which would silently wipe
	// the tenant_id and api_key an operator already filled in.
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite it (remove it first to regenerate)", filename)
		}
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// insecureConfigModeMask matches any group or world permission bit. A
// credential file should be 0600 (or 0400); anything looser exposes the API
// key to every local account.
const insecureConfigModeMask = 0o077

// checkConfigPermissions reports, as warning messages, a config file that is
// readable or writable by anyone other than its owner, or that is owned by
// neither root nor the user the agent runs as. It inspects the already-open
// handle so the check cannot race against a file swapped between open and
// stat.
//
// Windows is skipped: Unix mode bits and owners are synthesized by the Go
// runtime there and do not reflect the real ACL, so the check would be noise.
func checkConfigPermissions(file *os.File, filename string) []string {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := file.Stat()
	if err != nil {
		return []string{fmt.Sprintf("could not stat config file %s for a permission check: %v", filename, err)}
	}

	var warnings []string
	if mode := info.Mode().Perm(); mode&insecureConfigModeMask != 0 {
		warnings = append(warnings, fmt.Sprintf(
			"config file %s has overly permissive mode %#o: it contains the agent API key and any configured database/hypervisor passwords in cleartext; fix with: chmod 600 %s",
			filename, mode, filename))
	}
	if uid, ok := fileOwner(info); ok && uid != 0 && uid != os.Geteuid() {
		warnings = append(warnings, fmt.Sprintf(
			"config file %s is owned by uid %d, which is neither root nor the agent's user (uid %d): that account can change where the agent reports and what it trusts; fix with: chown root %s",
			filename, uid, os.Geteuid(), filename))
	}
	return warnings
}

// splitList reads a comma-separated value into its trimmed, non-empty items.
func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parseValue trims a raw value and, as in YAML, drops a trailing comment: a
// '#' preceded by whitespace starts one. A value that itself contains " #"
// (a password, say) is written in single or double quotes, which are removed.
func parseValue(raw string) string {
	v := strings.TrimSpace(raw)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : end+1]
		}
	}
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}

// isTruthy reports whether a config boolean is "true", "yes", "1" or "on",
// ignoring case.
func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "1", "on":
		return true
	}
	return false
}
