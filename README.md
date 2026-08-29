# Netwarden Agent

```
  _   _      _                         _
 | \ | | ___| |___      ____ _ _ __ __| | ___ _ __
 |  \| |/ _ \ __\ \ /\ / / _` | '__/ _` |/ _ \ '_ \
 | |\  |  __/ |_ \ V  V / (_| | | | (_| |  __/ | | |
 |_| \_|\___|\__| \_/\_/ \__,_|_|  \__,_|\___|_| |_|

```

**Enterprise-grade infrastructure monitoring agent** - A lightweight, secure, and high-performance monitoring agent written in Go that collects system, container, database, and custom metrics for the Netwarden monitoring platform.

[![Version](https://img.shields.io/badge/version-3.0.0--beta-blue)](https://github.com/netwardenhq/agent/releases)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Code Signed](https://img.shields.io/badge/windows-code%20signed-blue?logo=windows)](https://github.com/netwardenhq/agent/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/netwardenhq/agent)](https://goreportcard.com/report/github.com/netwardenhq/agent)
[![Downloads](https://img.shields.io/github/downloads/netwardenhq/agent/total)](https://github.com/netwardenhq/agent/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos%20%7C%20synology%20%7C%20wordpress-lightgrey)](https://netwarden.com)
[![Architecture](https://img.shields.io/badge/arch-amd64%20%7C%20arm64%20%7C%20armv7-orange)](https://netwarden.com)

## ✨ Key Features

- 🚀 **High Performance** - Minimal CPU (<1%) and memory (<50MB) footprint
- 🔒 **Secure by Design** - Runs as non-root, encrypted communications, secure token authentication
- 📊 **Comprehensive Monitoring** - System, container, database, VM, and process metrics
- 🐳 **Container Native** - Docker, Podman, and Kubernetes support
- 🗄️ **Database Monitoring** - PostgreSQL and MySQL/MariaDB health checks
- 🔄 **Smart Data Compression** - Delta compression and adaptive batching reduce bandwidth by 90%
- 🛡️ **Resilient** - Circuit breakers, automatic retries, and graceful degradation
- 🔧 **Zero Dependencies** - Single static binary, no runtime dependencies

## 🚀 Quick Start

### One-Line Installation

```bash
curl -sSL https://get.netwarden.com/install.sh | sudo bash -s -- --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY
```

This will:
1. ✅ Detect your OS and architecture
2. ✅ Download and install the appropriate package
3. ✅ Configure the agent with your API key
4. ✅ Start the monitoring service
5. ✅ Begin sending metrics to Netwarden

## 📦 Installation Methods

### Method 1: Automatic Installation (Recommended)

The install script automatically detects your system and installs the appropriate package:

```bash
# Download and run installer
curl -sSL https://get.netwarden.com/install.sh -o install.sh
chmod +x install.sh

# Install with your credentials (get from Netwarden dashboard)
sudo ./install.sh --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY

# Additional options
sudo ./install.sh --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY --version latest  # Latest version
sudo ./install.sh --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY --skip-start      # Don't start service
sudo ./install.sh --test                                    # Test mode only
```

### Method 2: Package Manager Installation

#### RPM-based Systems (RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux)

```bash
# Import GPG key
sudo rpm --import https://get.netwarden.com/rpm/RPM-GPG-KEY-netwarden

# Add repository
cat <<EOF | sudo tee /etc/yum.repos.d/netwarden.repo
[netwarden]
name=Netwarden Agent Repository
baseurl=https://get.netwarden.com/rpm/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://get.netwarden.com/rpm/RPM-GPG-KEY-netwarden
EOF

# Install agent
sudo yum install -y netwarden  # or dnf on Fedora

# Quick configuration one-liner (replace with your actual values from Netwarden dashboard)
TENANT_ID="your-tenant-id" API_KEY="your-api-key" && sudo sed -i "s/^tenant_id:.*/tenant_id: $TENANT_ID/; s/^api_key:.*/api_key: $API_KEY/" /etc/netwarden/netwarden.conf && sudo systemctl start netwarden

# Or configure manually
sudo nano /etc/netwarden/netwarden.conf
sudo systemctl enable --now netwarden
```

#### Direct RPM Installation

```bash
# Download latest package (choose your architecture)
curl -LO https://get.netwarden.com/netwarden-latest-x86_64.rpm     # Intel/AMD 64-bit
curl -LO https://get.netwarden.com/netwarden-latest-aarch64.rpm    # ARM 64-bit
curl -LO https://get.netwarden.com/netwarden-latest-armv7hl.rpm    # ARM 32-bit

# Import GPG key and verify
sudo rpm --import https://get.netwarden.com/rpm/RPM-GPG-KEY-netwarden
rpm --checksig netwarden-latest-x86_64.rpm  # Or your downloaded architecture

# Install
sudo rpm -ivh netwarden-latest-x86_64.rpm  # Or your downloaded architecture

# Quick configuration one-liner (replace with your actual values)
TENANT_ID="your-tenant-id" API_KEY="your-api-key" && sudo sed -i "s/^tenant_id:.*/tenant_id: $TENANT_ID/; s/^api_key:.*/api_key: $API_KEY/" /etc/netwarden/netwarden.conf && sudo systemctl start netwarden
```

#### DEB-based Systems (Ubuntu, Debian)

```bash
# Import GPG key
curl -fsSL https://get.netwarden.com/deb/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/netwarden.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/netwarden.gpg] https://get.netwarden.com/deb stable main" | sudo tee /etc/apt/sources.list.d/netwarden.list

# Update and install
sudo apt update
sudo apt install -y netwarden

# Quick configuration one-liner (replace with your actual values from Netwarden dashboard)
TENANT_ID="your-tenant-id" API_KEY="your-api-key" && sudo sed -i "s/^tenant_id:.*/tenant_id: $TENANT_ID/; s/^api_key:.*/api_key: $API_KEY/" /etc/netwarden/netwarden.conf && sudo systemctl start netwarden

# Or configure manually
sudo nano /etc/netwarden/netwarden.conf
sudo systemctl enable --now netwarden
```

#### Direct DEB Installation

```bash
# Download latest package (choose your architecture)
curl -LO https://get.netwarden.com/netwarden-latest-amd64.deb      # Intel/AMD 64-bit
curl -LO https://get.netwarden.com/netwarden-latest-arm64.deb      # ARM 64-bit
curl -LO https://get.netwarden.com/netwarden-latest-armhf.deb      # ARM 32-bit

# Install
sudo dpkg -i netwarden-latest-amd64.deb

# Fix any dependency issues
sudo apt-get install -f

# Quick configuration one-liner (replace with your actual values)
TENANT_ID="your-tenant-id" API_KEY="your-api-key" && sudo sed -i "s/^tenant_id:.*/tenant_id: $TENANT_ID/; s/^api_key:.*/api_key: $API_KEY/" /etc/netwarden/netwarden.conf && sudo systemctl start netwarden
```

### Method 3: macOS Installation

For macOS systems, download and install using our packaged tarballs:

```bash
# Download latest package for your macOS architecture
# macOS Apple Silicon (M1/M2/M3)
curl -LO https://get.netwarden.com/netwarden-latest-darwin-arm64.tar.gz

# macOS Intel
curl -LO https://get.netwarden.com/netwarden-latest-darwin-amd64.tar.gz

# Extract the package
tar -xzf netwarden-latest-darwin-*.tar.gz
cd netwarden-*-darwin-*

# Run the installation script
sudo ./scripts/install.sh

# The installer will:
# 1. Copy the binary to /usr/local/bin/netwarden
# 2. Create config directory at /usr/local/etc/netwarden
# 3. Install the configuration template
# 4. Show next steps for configuration
```

### Method 4: Windows Installation

For Windows systems, download and install using the Windows installer or standalone binary:

#### Windows Installer (Recommended)

```powershell
# Download installer for your architecture
# Intel/AMD 64-bit (most common)
https://get.netwarden.com/netwarden-latest-windows-amd64-installer.exe

# ARM64 (Surface Pro X, etc.)
https://get.netwarden.com/netwarden-latest-windows-arm64-installer.exe

# Run the installer - it will:
# 1. Install the binary to C:\Program Files\Netwarden\
# 2. Create config directory at C:\ProgramData\Netwarden\
# 3. Install as Windows Service
# 4. Prompt for API credentials
```

#### Standalone ZIP Package

```powershell
# Download ZIP for your architecture
# Intel/AMD 64-bit
https://get.netwarden.com/netwarden-latest-windows-amd64.zip

# ARM64
https://get.netwarden.com/netwarden-latest-windows-arm64.zip

# Extract and configure manually
# See Windows Configuration section below
```

#### Manual macOS Installation (Alternative)

```bash
# Extract and manually install
tar -xzf netwarden-latest-darwin-*.tar.gz
cd netwarden-*-darwin-*

# Copy binary
sudo cp bin/netwarden /usr/local/bin/
sudo chmod 755 /usr/local/bin/netwarden

# Create config directory and copy config
sudo mkdir -p /usr/local/etc/netwarden
sudo cp config/netwarden.conf /usr/local/etc/netwarden/

# Edit configuration with your API credentials
sudo vim /usr/local/etc/netwarden/netwarden.conf

# Test the configuration
netwarden --config /usr/local/etc/netwarden/netwarden.conf --validate-config

# Run the agent
netwarden --config /usr/local/etc/netwarden/netwarden.conf
```

## ⚙️ Configuration

### Quick Configuration (One-liner)

After installing the package, configure and start the agent with this one command:

```bash
# Replace with your actual values from the Netwarden dashboard
TENANT_ID="abc1234567" API_KEY="nw_sk_..." && \
  sudo sed -i "s/^tenant_id:.*/tenant_id: $TENANT_ID/; s/^api_key:.*/api_key: $API_KEY/" /etc/netwarden/netwarden.conf && \
  sudo systemctl start netwarden
```

### Manual Configuration

The agent configuration file is located at `/etc/netwarden/netwarden.conf`:

```yaml
# REQUIRED: Get these from your Netwarden dashboard
tenant_id: abc1234567     # Your 10-character tenant ID
api_key: nw_sk_...        # Your API key

# Optional: Override auto-detected hostname
# hostname: my-custom-hostname

# That's it! The agent will auto-configure everything else
```

### Getting Your Credentials

1. Log in to your [Netwarden Dashboard](https://app.netwarden.com)
2. Navigate to **Settings** → **Agent Tokens**
3. Click **Generate New Token**
4. Copy the `tenant_id` and `api_key`
5. Add them to `/etc/netwarden/netwarden.conf`

### Advanced Configuration

```yaml
# ==================== CORE SETTINGS ====================
tenant_id: abc1234567
api_key: nw_sk_...

# ==================== COLLECTION SETTINGS ====================
collection_interval: 60        # Seconds between collections (10-300)
batch_size: 100               # Metrics per batch (50-500)

# ==================== MONITORING TOGGLES ====================
collect_system_metrics: true      # CPU, memory, disk, network
collect_container_metrics: true   # Docker/Podman containers
collect_process_metrics: true     # Top processes by resource usage
enable_vms: true                  # Virtual machines (auto-detect)

# ==================== DATABASE MONITORING ====================
# PostgreSQL (uses TCP localhost:5432 by default)
enable_postgresql: true
postgresql_user: svc_netwarden
postgresql_password: your_password
# postgresql_host: localhost:5432        # Optional: defaults to localhost:5432
# postgresql_database: postgres          # Optional: defaults to postgres
# postgresql_socket: /var/run/postgresql # Optional: for Unix socket instead of TCP

# MySQL/MariaDB (uses TCP localhost:3306 by default)
enable_mysql: true
mysql_user: svc_netwarden
mysql_password: your_password
# mysql_host: localhost:3306             # Optional: defaults to localhost:3306
# mysql_socket: /var/run/mysqld/mysqld.sock # Optional: for Unix socket instead of TCP

# ==================== CONTAINER SETTINGS ====================
docker_socket: /var/run/docker.sock              # Docker socket
containerd_socket: /run/containerd/containerd.sock # Containerd socket

# ==================== PROCESS MONITORING ====================
process_cpu_threshold: 1.0      # Min CPU % to track process
process_memory_threshold: 50    # Min memory MB to track
max_tracked_processes: 100      # Limit tracked processes

# ==================== LOGGING ====================
log_level: info                          # debug, info, warn, error
# log_file: /var/log/netwarden.log       # Custom log location (optional, defaults to /var/log/netwarden.log)
```

## 🗄️ Database Monitoring Setup

The agent can monitor PostgreSQL and MySQL/MariaDB databases with connection health checks, performance metrics, replication status, and query statistics.

**Default Connection Method**: The agent uses **TCP connections** (localhost:5432 for PostgreSQL, localhost:3306 for MySQL) by default, which works out-of-the-box with standard database configurations. Unix socket connections are available as an opt-in option.

### PostgreSQL Monitoring

**Step 1: Create a monitoring user with minimal privileges**

```sql
-- Connect as postgres superuser
sudo -u postgres psql

-- Create the monitoring user
CREATE USER svc_netwarden WITH PASSWORD 'your_secure_password';

-- Grant connection and monitoring permissions
GRANT CONNECT ON DATABASE postgres TO svc_netwarden;
GRANT pg_monitor TO svc_netwarden;  -- PostgreSQL 10+

-- Exit
\q
```

**For PostgreSQL 9.6 and older** (without pg_monitor role):
```sql
CREATE USER svc_netwarden WITH PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE postgres TO svc_netwarden;
GRANT SELECT ON pg_stat_database TO svc_netwarden;
GRANT SELECT ON pg_stat_activity TO svc_netwarden;
GRANT SELECT ON pg_locks TO svc_netwarden;
```

**Step 2: Configure the agent**

Add to `/etc/netwarden/netwarden.conf`:
```yaml
enable_postgresql: true
postgresql_user: svc_netwarden
postgresql_password: your_secure_password
# Optional: Only needed if PostgreSQL is not on localhost:5432
# postgresql_host: localhost:5432
# postgresql_database: postgres
```

**Step 3: Test the connection**

```bash
# Test with psql (uses TCP connection)
psql -h 127.0.0.1 -U svc_netwarden -d postgres -c "SELECT version();"

# Restart the agent to apply changes
sudo systemctl restart netwarden
```

**Collected Metrics:**
- Connection count (active, idle, idle in transaction)
- Transaction statistics (commits, rollbacks)
- Buffer cache hit ratio
- Database size and dead tuples
- Lock count
- Replication lag (if replica)
- Slow query count (if pg_stat_statements enabled)

### MySQL/MariaDB Monitoring

**Step 1: Create a monitoring user with minimal privileges**

```sql
-- Connect as root
sudo mysql

-- Create the monitoring user
CREATE USER 'svc_netwarden'@'localhost' IDENTIFIED BY 'your_secure_password';

-- Grant minimal required permissions
GRANT PROCESS ON *.* TO 'svc_netwarden'@'localhost';
GRANT REPLICATION CLIENT ON *.* TO 'svc_netwarden'@'localhost';

-- Apply privileges
FLUSH PRIVILEGES;

-- Exit
exit;
```

**Step 2: Configure the agent**

Add to `/etc/netwarden/netwarden.conf`:
```yaml
enable_mysql: true
mysql_user: svc_netwarden
mysql_password: your_secure_password
# Optional: Only needed if MySQL is not on localhost:3306
# mysql_host: localhost:3306
```

**Step 3: Test the connection**

```bash
# Test with mysql client (uses TCP connection)
mysql -h 127.0.0.1 -u svc_netwarden -p -e "SELECT VERSION();"

# Restart the agent to apply changes
sudo systemctl restart netwarden
```

**Collected Metrics:**
- Connection count (current, max used)
- Query statistics (total queries, slow queries)
- InnoDB buffer pool metrics and hit ratio
- Table lock wait statistics
- Replication lag (if replica)

### Advanced: Unix Socket Connections (Optional)

If you prefer Unix socket connections instead of TCP, you can explicitly configure socket paths:

**PostgreSQL with socket:**
```yaml
enable_postgresql: true
postgresql_socket: /var/run/postgresql
postgresql_user: svc_netwarden
postgresql_password: your_secure_password
```

**MySQL with socket:**
```yaml
enable_mysql: true
mysql_socket: /var/run/mysqld/mysqld.sock
mysql_user: svc_netwarden
mysql_password: your_secure_password
```

**Note:** Socket connections require additional pg_hba.conf configuration for PostgreSQL. TCP connections (default) work with standard database configurations without additional setup.

## 🐳 Container Monitoring Setup

The agent automatically detects and monitors Docker, Podman, and Containerd containers without additional configuration.

### Docker Monitoring

For Docker containers, the agent needs access to the Docker socket:

```bash
# Default Docker socket location (auto-detected)
# /var/run/docker.sock

# If running agent in a container, mount the Docker socket:
docker run -v /var/run/docker.sock:/var/run/docker.sock netwarden-agent

# For rootless Docker, specify the socket path in config:
# docker_socket: /run/user/1000/docker.sock
```

**Collected Metrics:**
- Container count (running, stopped, total)
- CPU usage per container
- Memory usage and limits
- Network I/O statistics
- Disk I/O statistics
- Container state and health status

### Podman Monitoring

Podman is automatically detected and monitored:

```bash
# For rootless Podman (default)
# Socket: /run/user/$UID/podman/podman.sock

# For root Podman
# Socket: /run/podman/podman.sock

# Enable in config (auto-detected by default):
enable_containers: true
container_runtime: podman  # or auto
```

### Kubernetes/Containerd Monitoring

For Kubernetes environments using containerd:

```yaml
# In netwarden.conf:
enable_containers: true
container_runtime: containerd
containerd_socket: /run/containerd/containerd.sock
```

**Note:** The agent needs appropriate permissions to access the container runtime socket. Typically this means:
- Being in the `docker` group for Docker
- Running as the same user for rootless containers
- Having read permissions on the socket file

### Troubleshooting Container Monitoring

```bash
# Check if Docker is accessible
docker ps

# Check socket permissions
ls -la /var/run/docker.sock

# Test agent container detection
sudo netwarden --config /etc/netwarden/netwarden.conf
# Look for "Container collector initialized" in logs

# For permission issues, add agent user to docker group:
sudo usermod -aG docker netwarden
sudo systemctl restart netwarden
```

## 🖥️ Virtual Machine Monitoring

The agent can monitor virtual machines across multiple hypervisors including Proxmox, libvirt (KVM/QEMU/Xen), and more.

### Proxmox VE Monitoring

To monitor Proxmox virtual machines:

1. **Create a monitoring user in Proxmox:**
```bash
# On Proxmox server, create read-only user
pveum user add monitoring@pve --comment "Netwarden Monitoring"
pveum passwd monitoring@pve  # Set password
pveum aclmod / -user monitoring@pve -role PVEAuditor
```

2. **Configure the agent:**
```yaml
# In netwarden.conf:
enable_vms: true
vm_hypervisor: proxmox

# Proxmox API settings
proxmox_api: https://proxmox.example.com:8006
proxmox_username: monitoring@pve
proxmox_password: your_password

# Optional: Monitor specific node only
# proxmox_node: node1

# For self-signed certificates:
# proxmox_skip_tls_verify: true
```

3. **Using API tokens (recommended):**
```bash
# Create API token in Proxmox
pveum user token add monitoring@pve netwarden-agent

# Use token in config instead of password:
# proxmox_token_id: monitoring@pve!netwarden-agent
# proxmox_token_secret: uuid-token-secret-here
```

**Collected Metrics:**
- VM count (running, stopped, total)
- CPU usage per VM
- Memory usage per VM
- Disk I/O statistics
- Network I/O statistics
- VM state and uptime

### KVM/QEMU Monitoring (via libvirt)

For KVM, QEMU, or Xen hypervisors using libvirt:

1. **Grant libvirt access:**
```bash
# Add agent user to libvirt group
sudo usermod -aG libvirt netwarden
sudo systemctl restart netwarden
```

2. **Configure the agent:**
```yaml
# In netwarden.conf:
enable_vms: true
vm_hypervisor: libvirt  # or auto for auto-detection

# Libvirt connection (default: local system)
libvirt_uri: qemu:///system

# For remote libvirt host:
# libvirt_uri: qemu+ssh://user@host/system

# Custom socket path if needed:
# libvirt_socket: /var/run/libvirt/libvirt-sock
```

3. **Test libvirt connection:**
```bash
# List VMs to verify access
virsh -c qemu:///system list --all

# Check socket permissions
ls -la /var/run/libvirt/libvirt-sock
```

### Hyper-V Monitoring (Windows)

For Windows Hyper-V hosts:

```yaml
# In netwarden.conf:
enable_vms: true
vm_hypervisor: auto  # Auto-detects Hyper-V on Windows
```

The agent automatically detects and monitors Hyper-V VMs when running on a Windows host with Hyper-V enabled.

### VM Monitoring Configuration Options

```yaml
# ==================== VM MONITORING ====================
enable_vms: true                    # Enable VM monitoring
vm_hypervisor: auto                 # auto, proxmox, libvirt, kvm, xen, qemu
vm_stats_interval: 60s              # How often to collect VM stats

# Include/exclude specific VMs (regex patterns)
# vm_include: ["prod-*", "db-*"]   # Only monitor these VMs
# vm_exclude: ["test-*", "dev-*"]  # Exclude these VMs

# Performance tuning
# vm_timeout: 30s                  # Timeout for hypervisor operations
# vm_cache_timeout: 300s           # Cache VM list for 5 minutes
# vm_parallel_stats: 10            # Query 10 VMs in parallel
```

### Troubleshooting VM Monitoring

```bash
# Check if VMs are detected
grep -i "vm" /var/log/netwarden.log

# Test hypervisor connection
# For Proxmox:
curl -k https://proxmox.example.com:8006/api2/json/nodes

# For libvirt:
virsh list --all

# Common issues:
# - Permission denied: Add agent user to libvirt/qemu groups
# - Connection refused: Check hypervisor API is accessible
# - No VMs detected: Verify vm_hypervisor setting
# - High CPU usage: Increase vm_stats_interval
```

### Security Considerations for VM Monitoring

1. **Use read-only accounts** - Create monitoring-specific users with minimal privileges
2. **Use API tokens** instead of passwords where possible (Proxmox)
3. **Restrict network access** - Use firewall rules to limit API access
4. **Monitor over private networks** - Avoid exposing hypervisor APIs to public internet
5. **Use TLS/SSL** - Don't skip certificate verification in production

## 🚦 Service Management

### Starting and Stopping

```bash
# Start the agent
sudo systemctl start netwarden

# Stop the agent
sudo systemctl stop netwarden

# Restart the agent
sudo systemctl restart netwarden

# Enable auto-start on boot
sudo systemctl enable netwarden

# Check service status
sudo systemctl status netwarden
```

### Viewing Logs

```bash
# View recent logs
sudo journalctl -u netwarden -n 50

# Follow logs in real-time
sudo journalctl -u netwarden -f

# View log file directly
sudo tail -f /var/log/netwarden.log
```

### Troubleshooting

```bash
# Check connectivity to Netwarden API
curl -I https://api.netwarden.com

# Verify agent is running
ps aux | grep netwarden

# Check agent version
netwarden --version
```

---

## 👨‍💻 Developer Documentation

### Architecture Overview

The Netwarden Agent is designed with three core principles:

1. **Performance First** - Minimal resource usage through efficient Go code, smart caching, and delta compression
2. **Security by Default** - Runs as non-root, validates all inputs, uses secure communications
3. **Production Reliability** - Circuit breakers, retries, graceful degradation, comprehensive logging

#### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Netwarden Agent                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   CPU        │  │   Memory     │  │   Disk       │      │
│  │   Collector  │  │   Collector  │  │   Collector  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│  ┌──────▼──────────────────▼──────────────────▼──────┐      │
│  │             Collector Registry                      │      │
│  └─────────────────────┬───────────────────────────────┘      │
│                        │                                      │
│  ┌─────────────────────▼────────────────────────────┐        │
│  │          Metrics Processing Pipeline              │        │
│  │  ┌─────────┐  ┌──────────┐  ┌───────────────┐  │        │
│  │  │ Delta   │→│ Adaptive │→│ Compression    │  │        │
│  │  │ Tracker │  │ Batcher  │  │ (gzip)        │  │        │
│  │  └─────────┘  └──────────┘  └───────────────┘  │        │
│  └─────────────────────┬────────────────────────────┘        │
│                        │                                      │
│  ┌─────────────────────▼────────────────────────────┐        │
│  │          HTTP/2 Transmitter                       │        │
│  │  with Circuit Breaker & Retry Logic               │        │
│  └─────────────────────┬────────────────────────────┘        │
│                        │                                      │
└────────────────────────┼──────────────────────────────────────┘
                         │
                         ▼
               Netwarden Platform API
```

### Project Structure

```
agent/
├── cmd/
│   └── netwarden/
│       └── main.go              # Entry point, CLI flags, daemon mode
│
├── internal/
│   ├── agent/
│   │   ├── agent.go            # Core agent orchestration
│   │   ├── transmitter.go      # HTTP/2 client, compression
│   │   ├── collectors_linux.go # Linux-specific collectors
│   │   └── collectors_nonlinux.go # Cross-platform collectors
│   │
│   ├── collectors/              # Metric collection modules
│   │   ├── base.go             # Base collector implementation
│   │   ├── cpu/                # CPU usage and stats
│   │   ├── memory/             # Memory usage and stats
│   │   ├── disk/               # Disk usage and I/O
│   │   ├── network/            # Network interfaces and traffic
│   │   ├── container/          # Docker/Podman monitoring
│   │   │   ├── runtime_detector.go # Auto-detect container runtime
│   │   │   ├── docker_podman.go    # Container metrics collection
│   │   │   └── client.go           # Container API client
│   │   ├── postgresql/         # PostgreSQL monitoring
│   │   │   ├── postgresql.go   # Main PostgreSQL collector
│   │   │   └── postgresql_unix.go # Unix socket support
│   │   ├── mysql/              # MySQL/MariaDB monitoring
│   │   │   ├── mysql.go        # Main MySQL collector
│   │   │   └── mysql_unix.go   # Unix socket support
│   │   ├── process/            # Process monitoring
│   │   │   ├── process.go      # Process collector
│   │   │   └── process_unix.go # Unix-specific process stats
│   │   ├── system/             # System information
│   │   │   ├── system.go       # OS info, uptime, users
│   │   │   └── users_unix.go   # Active user sessions
│   │   ├── updates/            # OS update checks
│   │   └── vm/                 # Virtual machine monitoring
│   │       ├── hypervisor.go   # Hypervisor detection
│   │       ├── libvirt.go      # KVM/QEMU via libvirt
│   │       └── proxmox.go      # Proxmox VE API
│   │
│   ├── metrics/                 # Metric types and processing
│   │   ├── types.go            # Metric data structures
│   │   ├── builder.go          # Metric construction helpers
│   │   ├── delta.go            # Delta compression tracker
│   │   ├── adaptive_batch.go   # Dynamic batch sizing
│   │   ├── simple.go           # Simple metric store
│   │   └── self.go             # Agent self-monitoring
│   │
│   ├── config/                  # Configuration management
│   │   ├── config.go           # Config parsing and validation
│   │   └── validation.go       # Input validation rules
│   │
│   ├── registry/                # Collector management
│   │   └── registry.go         # Dynamic collector registration
│   │
│   ├── resilience/              # Fault tolerance
│   │   ├── circuit_breaker.go  # Circuit breaker pattern
│   │   └── retry.go            # Exponential backoff retry
│   │
│   ├── security/                # Security features
│   │   ├── token.go            # API token validation
│   │   └── command.go          # Secure command execution
│   │
│   ├── compression/             # Data compression
│   │   └── gzip.go             # Gzip compression
│   │
│   └── errors/                  # Error handling
│       ├── errors.go           # Custom error types
│       ├── metrics.go          # Error metrics
│       └── recovery.go         # Panic recovery
│
├── build/                       # Build and packaging
│   ├── Dockerfile.multi-arch-builder # Multi-arch Docker builds
│   ├── netwarden-x86_64.spec  # RPM spec file (x86_64)
│   ├── netwarden-armv7hl.spec # RPM spec file (ARM)
│   ├── deb-amd64/              # Debian package structure
│   ├── rpm-x86_64/             # RPM package structure
│   └── rpm-armv7hl/            # ARM RPM structure
│
├── Makefile                     # Build automation
├── go.mod                       # Go module definition
├── go.sum                       # Dependency checksums
└── install.sh                   # Installation script
```

### Key Components

#### Collectors
Collectors are pluggable modules that gather specific types of metrics. Each collector implements the `Collector` interface:

```go
type Collector interface {
    Name() string                              // Unique collector name
    Collect(ctx context.Context) ([]Metric, error) // Gather metrics
    Enabled() bool                             // Check if enabled
    Close() error                              // Cleanup resources
}
```

Collectors are:
- **Isolated**: Each runs independently, failures don't affect others
- **Configurable**: Can be enabled/disabled via configuration
- **Efficient**: Use caching and rate limiting to minimize overhead
- **Platform-aware**: OS-specific implementations where needed

#### Registry
The Registry manages collector lifecycle:
- Dynamic registration of collectors at startup
- Parallel metric collection with timeout control
- Health checking and error tracking
- Graceful shutdown coordination

#### Transmitter
The HTTP/2 transmitter handles secure metric delivery:
- **Compression**: Gzip compression reduces payload by 85%
- **Batching**: Adaptive batch sizing based on network conditions
- **Resilience**: Circuit breaker prevents cascade failures
- **Security**: TLS 1.3, token authentication, certificate pinning

#### Delta Tracker
Reduces bandwidth by only sending changed metrics:
- Tracks previous values for each metric
- Sends full snapshots periodically (every 100 batches)
- Reduces data transmission by 90% for stable metrics

#### Adaptive Batcher
Dynamically adjusts batch size based on:
- Network latency
- Server response times
- Error rates
- Memory pressure

### Building from Source

#### Prerequisites
- Go 1.21 or higher
- Make (optional, for Makefile)
- Docker (optional, for multi-arch builds)

#### Build Commands

```bash
# Clone repository
git clone https://github.com/netwarden/netwarden-agent
cd netwarden-agent

# Build for current platform
go build -o netwarden-agent cmd/netwarden/main.go

# Build with version information
go build -ldflags "-X main.version=1.0.0 -X main.buildTime=$(date -u '+%Y-%m-%d_%H:%M:%S') -X main.gitCommit=$(git rev-parse HEAD)" -o netwarden-agent cmd/netwarden/main.go

# Cross-compile for different platforms
GOOS=linux GOARCH=amd64 go build -o netwarden-linux-amd64 cmd/netwarden/main.go
GOOS=linux GOARCH=arm64 go build -o netwarden-linux-arm64 cmd/netwarden/main.go
GOOS=darwin GOARCH=amd64 go build -o netwarden-darwin-amd64 cmd/netwarden/main.go
GOOS=windows GOARCH=amd64 go build -o netwarden-windows-amd64.exe cmd/netwarden/main.go

# Build all platforms with Make
make all

# Build packages
make rpm    # Build RPM packages
make deb    # Build DEB packages
make docker # Build Docker image
```

#### Creating Packages

**RPM Package:**
```bash
# Install rpmbuild
sudo yum install -y rpm-build

# Build RPM
rpmbuild -bb build/netwarden-x86_64.spec

# Package will be in ~/rpmbuild/RPMS/x86_64/
```

**DEB Package:**
```bash
# Install dpkg-dev
sudo apt-get install -y dpkg-dev

# Build DEB
dpkg-deb --build build/deb-amd64/netwarden-agent_VERSION_amd64

# Package will be in current directory
```

### Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test
go test -v ./internal/collectors/cpu

# Benchmark collectors
go test -bench=. ./internal/collectors/...

# Integration test
go test -tags=integration ./...
```

### Performance Profiling

```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=. ./internal/metrics
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof -bench=. ./internal/metrics
go tool pprof mem.prof
```

## 🔒 Security Considerations

### Agent Security

- **Non-root Execution**: Agent runs as dedicated `netwarden` user
- **Minimal Privileges**: Only requires read access to system metrics
- **No Network Listening**: Agent only makes outbound HTTPS connections
- **Secure Storage**: API keys stored with 600 permissions
- **Input Validation**: All configuration inputs are validated
- **Memory Safety**: Written in Go with automatic memory management

### Network Security

- **TLS 1.3**: Modern encryption for all communications
- **Certificate Validation**: Strict certificate checking
- **Token Authentication**: Secure bearer token authentication
- **No Sensitive Data**: Metrics contain no PII or secrets
- **Firewall Friendly**: Only requires outbound HTTPS (443)

### Best Practices

1. **Rotate API Keys**: Regularly rotate API keys (every 90 days)
2. **Restrict Config Access**: Ensure `/etc/netwarden/netwarden.conf` is readable only by root/netwarden
3. **Use Monitoring User**: For databases, always use dedicated monitoring users with minimal privileges
4. **Review Logs**: Regularly review agent logs for anomalies
5. **Update Regularly**: Keep agent updated for security patches

## 🐛 Troubleshooting

### Common Issues

#### Agent Won't Start

```bash
# Common issues:
# - Missing or invalid tenant_id (must be 10 characters)
# - Invalid api_key format (must start with nw_sk_)
# - Port 443 blocked by firewall
# - Configuration file syntax errors
```

#### No Metrics Appearing

```bash
# Check connectivity
curl -I https://api.netwarden.com

# Check agent logs for errors
journalctl -u netwarden -n 100 | grep ERROR

# Verify configuration
cat /etc/netwarden/netwarden.conf | grep -E '(tenant_id|api_key)'
```

#### High CPU Usage

```bash
# Check collection interval (minimum 10 seconds)
grep collection_interval /etc/netwarden/netwarden.conf

# Disable expensive collectors
# In netwarden.conf:
collect_container_metrics: false
collect_process_metrics: false
```

#### Database Connection Failed

```bash
# Test PostgreSQL connection
psql -h localhost -U monitoring_user -d postgres -c "SELECT 1"

# Test MySQL connection
mysql -h localhost -u monitoring_user -p -e "SELECT 1"

# Check socket paths
ls -la /var/run/postgresql/.s.PGSQL.5432
ls -la /var/run/mysqld/mysqld.sock
```

### Debug Mode

Run agent in foreground with debug logging:

```bash
# Stop service
sudo systemctl stop netwarden

# Set debug in config file:
# log_level: debug

# Run in foreground
sudo netwarden --config /etc/netwarden/netwarden.conf
```

### Performance Tuning

For high-load systems:

```yaml
# Increase collection interval
collection_interval: 120

# Increase batch size
batch_size: 500

# Limit process tracking
max_tracked_processes: 50
process_cpu_threshold: 5.0
process_memory_threshold: 100

# Disable non-critical collectors
enable_vms: false
```

## 📝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/netwarden-agent
cd netwarden-agent

# Install dependencies
go mod download

# Run tests
make test

# Build locally
make build
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Community Support

- 📧 Email: support@netwarden.com
- 💬 Discord: [discord.gg/netwarden](https://discord.gg/netwarden)
- 🐛 Issues: [GitHub Issues](https://github.com/netwarden/netwarden-agent/issues)
- 📖 Docs: [docs.netwarden.com](https://docs.netwarden.com)

### Commercial Support

Enterprise support plans available at [netwarden.com/enterprise](https://netwarden.com/enterprise)

---

Built with ❤️ by the Netwarden team | [netwarden.com](https://netwarden.com)