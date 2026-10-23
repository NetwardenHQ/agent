# Netwarden Agent

```
  _   _      _                         _
 | \ | | ___| |___      ____ _ _ __ __| | ___ _ __
 |  \| |/ _ \ __\ \ /\ / / _` | '__/ _` |/ _ \ '_ \
 | |\  |  __/ |_ \ V  V / (_| | | | (_| |  __/ | | |
 |_| \_|\___|\__| \_/\_/ \__,_|_|  \__,_|\___|_| |_|

```

The Netwarden agent is a small Go program that collects system, container,
database, VM, Kubernetes and security-posture data and sends it to the
Netwarden platform.

[![Version](https://img.shields.io/badge/version-3.3.0-blue)](https://github.com/NetwardenHQ/agent/releases)
[![Go Version](https://img.shields.io/badge/go-1.27%2B-00ADD8)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Code Signed](https://img.shields.io/badge/windows-code%20signed-blue?logo=windows)](https://github.com/NetwardenHQ/agent/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/NetwardenHQ/agent)](https://goreportcard.com/report/github.com/NetwardenHQ/agent)
[![Downloads](https://img.shields.io/github/downloads/NetwardenHQ/agent/total)](https://github.com/NetwardenHQ/agent/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos%20%7C%20freebsd-lightgrey)](https://netwarden.com)
[![Architecture](https://img.shields.io/badge/arch-amd64%20%7C%20arm64%20%7C%20armv7-orange)](https://netwarden.com)

## Features

- **Small footprint.** About 16 MB resident and well under 1% of one core at a 10-second interval. One static binary, no runtime dependencies.
- **Outbound only.** TLS to the platform, bearer-token authentication, no listening ports.
- **Metrics.** System, containers (Docker, Podman), databases (PostgreSQL, MySQL/MariaDB), VMs (libvirt, Proxmox), in-cluster Kubernetes, application processes, OPNsense firewalls.
- **Security posture.** Failed logins, sshd configuration, listening ports, installed packages (OS and pip/npm), CIS benchmarks, file integrity.
- **Delta transmission.** Only metrics that changed or aged out are sent, so a stable host costs a few KB per cycle.
- **Partial failure.** Retries with backoff, honours rate limits, and keeps running when individual collectors fail.

## Quick Start

```bash
curl -sSL https://get.netwarden.com/install.sh | sudo bash -s -- --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY
```

The script detects the OS and architecture, installs the matching package,
writes your credentials to the config file and starts the service.

## Installation

### Install script

```bash
curl -sSL https://get.netwarden.com/install.sh -o install.sh
chmod +x install.sh

# Credentials come from the Netwarden dashboard
sudo ./install.sh --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY

# Other options
sudo ./install.sh --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY --version latest
sudo ./install.sh --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY --skip-start   # install, don't start
sudo ./install.sh --test                                                            # test mode only
```

### RPM-based systems (RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux)

```bash
sudo rpm --import https://get.netwarden.com/rpm/RPM-GPG-KEY-netwarden

cat <<EOF | sudo tee /etc/yum.repos.d/netwarden.repo
[netwarden]
name=Netwarden Agent Repository
baseurl=https://get.netwarden.com/rpm/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://get.netwarden.com/rpm/RPM-GPG-KEY-netwarden
EOF

sudo dnf install -y netwarden   # or yum

sudo nano /etc/netwarden/netwarden.conf   # set tenant_id and api_key
sudo systemctl enable --now netwarden
```

Single RPM without the repository:

```bash
curl -LO https://get.netwarden.com/netwarden-latest-x86_64.rpm     # x86-64
curl -LO https://get.netwarden.com/netwarden-latest-aarch64.rpm    # ARM 64-bit
curl -LO https://get.netwarden.com/netwarden-latest-armv7hl.rpm    # ARM 32-bit

sudo rpm --import https://get.netwarden.com/rpm/RPM-GPG-KEY-netwarden
rpm --checksig netwarden-latest-x86_64.rpm
sudo rpm -ivh netwarden-latest-x86_64.rpm
```

### DEB-based systems (Debian, Ubuntu)

```bash
curl -fsSL https://get.netwarden.com/deb/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/netwarden.gpg
echo "deb [signed-by=/usr/share/keyrings/netwarden.gpg] https://get.netwarden.com/deb stable main" | sudo tee /etc/apt/sources.list.d/netwarden.list

sudo apt update
sudo apt install -y netwarden

sudo nano /etc/netwarden/netwarden.conf   # set tenant_id and api_key
sudo systemctl enable --now netwarden
```

Single DEB without the repository:

```bash
curl -LO https://get.netwarden.com/netwarden-latest-amd64.deb      # x86-64
curl -LO https://get.netwarden.com/netwarden-latest-arm64.deb      # ARM 64-bit
curl -LO https://get.netwarden.com/netwarden-latest-armhf.deb      # ARM 32-bit

sudo dpkg -i netwarden-latest-amd64.deb
sudo apt-get install -f
```

### macOS

```bash
curl -fsSL https://get.netwarden.com/install.sh | sudo bash -s -- --tenant-id YOUR_TENANT_ID --api-key YOUR_API_KEY
```

The installer verifies the download against the SHA-256 in
`https://get.netwarden.com/latest.json`, installs `/usr/local/bin/netwarden`,
writes `/etc/netwarden/netwarden.conf` (mode 600) and runs the agent as the
launchd daemon `com.netwarden.agent`, which starts at boot. Re-running it
upgrades in place and keeps the config.

```bash
sudo launchctl print system/com.netwarden.agent          # status
sudo launchctl kickstart -k system/com.netwarden.agent   # restart
```

To install by hand, take the tarball for your Mac
(`netwarden-latest-macos-arm64.tar.gz` for Apple silicon,
`netwarden-latest-macos-intel.tar.gz` for Intel); it contains the `netwarden`
binary.

### Windows

Installer (installs to `C:\Program Files\Netwarden\`, registers the Windows
service and prompts for credentials):

- x86-64: https://get.netwarden.com/netwarden-latest-windows-amd64-installer.exe
- ARM64: https://get.netwarden.com/netwarden-latest-windows-arm64-installer.exe

ZIP for a manual install:

- x86-64: https://get.netwarden.com/netwarden-latest-windows-amd64.zip
- ARM64: https://get.netwarden.com/netwarden-latest-windows-arm64.zip

Without `--config`, the agent reads `netwarden.conf` from the directory of the
executable.

### FreeBSD and OPNsense

See [Installing on FreeBSD and OPNsense](#installing-on-freebsd-and-opnsense).

## Configuration

### Default paths

| OS | Config file | Log file |
|---|---|---|
| Linux, macOS | `/etc/netwarden/netwarden.conf` | `/var/log/netwarden/netwarden.log` |
| FreeBSD | `/usr/local/etc/netwarden/netwarden.conf` | `/var/log/netwarden/netwarden.log` |
| Windows | `netwarden.conf` next to the executable | `netwarden.log` next to the executable |

`-c` / `--config` overrides the config path. If the log file cannot be opened
the agent logs to stderr.

### Minimal configuration

```yaml
tenant_id: abc1234567     # 10 characters, from the Netwarden dashboard
api_key: nw_sk_...        # agent API key
# hostname: my-server     # default: the system hostname
```

To get credentials, sign in to the [Netwarden dashboard](https://app.netwarden.com),
open **Settings > Agent Tokens**, generate a token and copy `tenant_id` and `api_key`.

### Format

`netwarden --create-config` writes an example file that documents every key.
It refuses to overwrite an existing file.

Each line is `key: value`. Lines starting with `#` are comments, and a `#`
preceded by a space or tab starts a trailing comment. A value that itself
contains ` #` must be quoted (`"..."` or `'...'`). Booleans accept
`true/false`, `yes/no`, `on/off` and `1/0`.

Keep the file mode `0600`: it holds the API key and any database or hypervisor
passwords. The agent warns at startup when the file is readable by group or
others, or owned by neither root nor the user the agent runs as.

### All keys

```yaml
# ---- Core ----
tenant_id: abc1234567
api_key: nw_sk_...
# server_url: https://netwarden.example.com   # self-hosted platform (default: https://api.netwarden.com)
# tls_ca_cert: /etc/netwarden/ca.pem          # trust a private CA
# tls_skip_verify: false                      # insecure; test servers only
# hostname: my-server

# ---- Logging ----
log_level: info                               # debug, info, warn, error
# log_file: /var/log/netwarden/netwarden.log

# ---- Self-update (Windows, Linux packages, macOS, FreeBSD, Kubernetes; off on OPNsense) ----
# self_update: true
# self_update_window_start: 1                 # local hour the window opens
# self_update_window_end: 5                   # local hour it closes
# self_update_url: https://mirror.internal/netwarden-{version}-{os}-{arch}-installer.exe
# self_update_signers: spki-sha256:<hex>      # replaces the built-in signer list;
#                                             # also sha256:<cert thumbprint>; an exact CN
#                                             # is accepted for the Windows installer only

# ---- Resource collectors (on by default) ----
# enable_cpu: true
# enable_memory: true
# enable_system: true
# enable_disk: true
# enable_network: true
# network_interfaces: eth0,eth1               # only these (default: auto-detect)
# network_exclude: wg*,tun*                   # extra patterns to ignore

# ---- Containers (on by default; inactive without a runtime) ----
# enable_containers: true
# container_runtime: auto                     # auto, docker, podman
# container_socket: /var/run/docker.sock
# container_stats_interval: 120               # seconds

# ---- Virtual machines (Linux only; on by default; inactive without a hypervisor) ----
# enable_vms: true
# vm_hypervisor: auto                         # auto, proxmox, libvirt (kvm, xen, qemu are aliases)
# See "Virtual Machine Monitoring" for the remaining vm_*, libvirt_* and proxmox_* keys.

# ---- Kubernetes (on by default; active only inside a cluster) ----
# enable_kubernetes: true
# k8s_enable_jobs: true                       # each must match the RBAC the manifest grants
# k8s_enable_availability: true
# k8s_enable_resources: true
# k8s_enable_cnpg: true
# k8s_enable_ingress: true

# ---- Databases (off by default) ----
# enable_postgresql: false                    # see "Database Monitoring"
# enable_mysql: false

# ---- Application processes (off by default; defined in the Netwarden UI) ----
# enable_process_monitoring: false

# ---- Security posture (on by default) ----
# enable_security: true                       # master switch for the next four keys
# enable_security_auth: true                  # failed-login counts (journald / auth.log)
# enable_security_sshconfig: true             # sshd_config audit
# enable_security_ports: true                 # listening sockets, every 5 minutes
# enable_security_packages: true              # installed OS packages, every 6 hours
# enable_security_lang_packages: true         # pip / npm packages installed on the host
# language_package_roots: /srv/app            # extra directories to scan for node_modules
# enable_cis: true                            # runs only when a CIS profile is set in the UI
# enable_opnsense: true                       # OPNsense only; inactive elsewhere

# ---- File integrity (off by default) ----
# enable_fim: false
# enable_fim_realtime: true                   # default off on macOS and FreeBSD
# fim_manifest_path: /var/lib/netwarden/fim-manifest
# fim_roots: /etc/myapp,/opt/myapp/bin

# ---- Spool for local producers ----
# spool_dir: /var/lib/netwarden/spool         # "off" disables it
```

The reporting interval is not set here. The platform sets it per plan, and the
agent fetches it at startup and about once an hour after that.

## File Integrity Monitoring

With `enable_fim: true` the agent hashes a fixed set of high-value paths
(binaries, sudoers, PAM and sshd configuration, account files, systemd units,
cron, and the Windows equivalents) with SHA-256, records mode and owner, and
reports changes. `fim_roots` adds paths.

A full walk runs every hour. Real-time watching (inotify on Linux,
ReadDirectoryChangesW on Windows) reports changes within seconds between
walks. It is on by default on Linux and Windows and off on macOS and FreeBSD,
where kqueue needs an open descriptor for every watched file. Set
`enable_fim_realtime: true` to enable it there, or `false` to disable it
anywhere.

The baseline is stored at `fim_manifest_path`:

| OS | Default |
|---|---|
| Linux, macOS | `/var/lib/netwarden/fim-manifest` |
| FreeBSD | `/var/db/netwarden/fim-manifest` |
| Windows | `%ProgramData%\Netwarden\fim-manifest` |

The agent trusts a baseline only when the file and its directory are owned by
root or the agent's user and not writable by group or others. On Windows they
must be owned by SYSTEM, Administrators or the agent's account. Changes are held until the
platform acknowledges them, so a failed post does not lose them.

## OPNsense Monitoring

On an OPNsense firewall the agent enables the `opnsense` collector
(`enable_opnsense: true` is the default; the collector does nothing on other
hosts). Run the agent as root so it can read the firewall's logs and run
`configctl` and `pfctl`. The collector only reads.

| Source | Metrics (prefix `opnsense_`) |
|---|---|
| Gateways (`configctl interface gateways status`) | `gateway_up`, `gateway_degraded`, `gateway_latency_ms`, `gateway_jitter_ms`, `gateway_loss_percent` per gateway |
| Firmware (OPNsense's update check, `/tmp/pkg_upgrade.json`) | `firmware_upgrade_packages`, `firmware_new_packages`, `firmware_remove_packages`, `firmware_major_upgrade_available`, `reboot_required`, `firmware_check_ok`, `firmware_check_age_seconds`, `info` (product version) |
| Packet filter (`pfctl -si`, `-sm`) | `pf_states`, `pf_states_limit`, `pf_state_usage_percent`, `pf_enabled`, state and counter totals |
| Suricata (`/var/log/suricata/eve.json`) | `ids_enabled`, `ids_ips_mode`, `ids_running`, `ids_alerts`, `ids_alerts_by_severity`, `ids_blocked`, `ids_top_sources`, `ids_top_signature`, `ids_kernel_drops` |
| Filter log (`/var/log/filter/`) | `filter_blocked` and `filter_passed` per interface, `filter_blocked_top_sources`, `filter_blocked_top_ports` |
| Audit log (`/var/log/audit/`) | `login_failures` and `login_successes` for the GUI and SSH, plus the `security_failed_logins*` family used on Linux |
| CARP | `carp_vhids` by state, `carp_demotion` (only on firewalls with CARP addresses) |
| Configuration | `config_last_change_age_seconds`, `config_last_change_timestamp` (user and description as labels), `config_backups` |

Log-derived metrics count the interval since the previous cycle. The first
cycle after startup only records where each log ends, so it reports no log
counts. A source that cannot be read (for example, IDS enabled but `eve.json`
missing) logs one warning and reports nothing; the agent does not substitute
zeros. Suricata kernel counters arrive with Suricata's own stats event, every
five minutes by default.

### Installing on FreeBSD and OPNsense

The agent ships as a FreeBSD package, `netwarden-agent-<version>.pkg`, built
for FreeBSD 14 and 15 on amd64 and arm64. It installs
`/usr/local/sbin/netwarden-agent`, an rc.d script, a newsyslog rule and a
sample config, and keeps state in `/var/db/netwarden`.

```sh
fetch -o - https://get.netwarden.com/install-freebsd.sh | sh -s -- --tenant-id ID --api-key KEY
```

The script picks the package for the host's FreeBSD release and architecture,
verifies its SHA-256, writes the credentials to
`/usr/local/etc/netwarden/netwarden.conf` (mode 600), enables the service in
`/etc/rc.conf.d/netwarden` (OPNsense rewrites `rc.conf`) and starts it.

`daemon(8)` supervises the agent and restarts it if it exits. The log,
`/var/log/netwarden/netwarden.log`, rotates daily or at 1 MB with 7 kept, and
the agent reopens it on SIGHUP. Removing the package stops the agent and
deletes the config only if it is still the unedited sample.

## Device Identity and Spool

Every agent sends a `device_identity` snapshot each cycle:

- `role`: `gateway` when the OPNsense collector is active, `cluster` for the in-cluster agent, otherwise `server`.
- `platform` (`ubuntu`, `opnsense`, `freebsd`, `darwin`, `windows`, ...), `platform_version` and `vendor` (`Deciso` on OPNsense).
- `capabilities`, on OPNsense only, and only what `config.xml` or the filesystem shows: `firewall` and `nat` always, then `ids`, `vpn`, `dhcp`, `dns`, `crowdsec`.
- `interfaces`: name, MAC and CIDR addresses, without loopback or link-local. On OPNsense each also has a `role` (`wan`, `lan`, `vpn`, `other`) from `config.xml`.

Values the agent cannot determine are omitted. Nothing secret from
`config.xml` is kept.

The agent also forwards files that local producers, such as an OPNsense UI
plugin, leave in a spool directory. The file formats and the agent's
`state.json` are a public interface, documented in
[docs/spool.md](docs/spool.md).

| File | Sent as | When |
|---|---|---|
| `events/*.jsonl` | `events` | each cycle while non-empty, at most 500 per post, at least once |
| `exposure.json` | `network_exposure` | when its SHA-256 changes, and at least hourly (max 256 KB) |
| `identity.json` | merged into `device_identity` | each cycle; only `unisense_version` (the producer's version) is accepted |

`spool_dir` sets the directory. The default is `/var/db/netwarden/spool` on
FreeBSD and `/var/lib/netwarden/spool` on Linux; on other systems the spool is
off unless `spool_dir` is set. `spool_dir: off` disables it. The agent ignores
a spool that is not owned by root or is writable by group or others, and does
not follow symlinks or read `*.tmp` files.

## Database Monitoring

The agent monitors PostgreSQL and MySQL/MariaDB over TCP to `localhost`
(ports 5432 and 3306) by default. Unix sockets are opt-in. Connections to a
remote host use TLS when the server offers it (`sslmode=prefer` for PostgreSQL,
`tls=preferred` for MySQL); sockets and loopback connect without TLS.

### PostgreSQL

Create a monitoring user:

```sql
-- sudo -u postgres psql
CREATE USER svc_netwarden WITH PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE postgres TO svc_netwarden;
GRANT pg_monitor TO svc_netwarden;  -- PostgreSQL 10+
```

PostgreSQL 9.6 and older have no `pg_monitor` role:

```sql
CREATE USER svc_netwarden WITH PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE postgres TO svc_netwarden;
GRANT SELECT ON pg_stat_database TO svc_netwarden;
GRANT SELECT ON pg_stat_activity TO svc_netwarden;
GRANT SELECT ON pg_locks TO svc_netwarden;
```

Configure the agent:

```yaml
enable_postgresql: true
postgresql_user: svc_netwarden
postgresql_password: your_secure_password
# postgresql_host: localhost:5432
# postgresql_database: postgres
```

Test and restart:

```bash
psql -h 127.0.0.1 -U svc_netwarden -d postgres -c "SELECT version();"
sudo systemctl restart netwarden
```

Collected: connections (active, idle, idle in transaction), commits and
rollbacks, buffer cache hit ratio, dead tuples, lock count, replication lag on
replicas, and slow queries when `pg_stat_statements` is enabled.

### MySQL / MariaDB

Create a monitoring user:

```sql
-- sudo mysql
CREATE USER 'svc_netwarden'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT PROCESS ON *.* TO 'svc_netwarden'@'localhost';
GRANT REPLICATION CLIENT ON *.* TO 'svc_netwarden'@'localhost';
FLUSH PRIVILEGES;
```

Configure the agent:

```yaml
enable_mysql: true
mysql_user: svc_netwarden
mysql_password: your_secure_password
# mysql_host: localhost:3306
```

Test and restart:

```bash
mysql -h 127.0.0.1 -u svc_netwarden -p -e "SELECT VERSION();"
sudo systemctl restart netwarden
```

Collected: connections (current, max used), total and slow queries, InnoDB
buffer pool reads and hit ratio, table lock waits, and replication lag on
replicas.

### Unix sockets

```yaml
enable_postgresql: true
postgresql_socket: /var/run/postgresql
postgresql_user: svc_netwarden
postgresql_password: your_secure_password
```

```yaml
enable_mysql: true
mysql_socket: /var/run/mysqld/mysqld.sock
mysql_user: svc_netwarden
mysql_password: your_secure_password
```

PostgreSQL socket connections usually need a matching `pg_hba.conf` entry.

## Container Monitoring

The agent detects Docker and Podman without configuration. With
`container_runtime: auto` it tries, in order, `/var/run/docker.sock`,
`/run/podman/podman.sock`, the current user's
`/run/user/<uid>/podman/podman.sock`, and the Docker Desktop named pipe on
Windows. When Podman is installed without its API socket (the default on
Debian and Ubuntu) it falls back to the `podman` CLI.

```yaml
enable_containers: true
container_runtime: podman                    # auto, docker, podman
container_socket: /run/user/1000/podman/podman.sock
```

The agent's user needs access to the socket: membership in the `docker`
group for Docker, or the same user for rootless Podman.

Collected: container counts by state, CPU (100 = one core), memory usage and
limit, network and block I/O, state, and a `container_images`
inventory deduplicated by image digest.

Troubleshooting:

```bash
docker ps                                    # is the runtime reachable?
ls -la /var/run/docker.sock
sudo usermod -aG docker netwarden            # grant access, then restart
sudo systemctl restart netwarden
grep -i container /var/log/netwarden/netwarden.log
```

## Virtual Machine Monitoring

On Linux the agent monitors libvirt (KVM, QEMU, Xen) and Proxmox VE guests.
With `vm_hypervisor: auto` it picks Proxmox when `/etc/pve`, `pvesh` or `qm` is
present, then libvirt.

### Proxmox VE

The Proxmox collector uses the API, so `proxmox_api` must be set. Create a
read-only user:

```bash
pveum user add monitoring@pve --comment "Netwarden"
pveum aclmod / -user monitoring@pve -role PVEAuditor
pveum user token add monitoring@pve netwarden-agent   # API token (preferred)
```

```yaml
enable_vms: true
vm_hypervisor: proxmox
proxmox_api: https://127.0.0.1:8006
proxmox_token_id: monitoring@pve!netwarden-agent
proxmox_token_secret: <token secret>
# Or password authentication:
# proxmox_username: monitoring@pve
# proxmox_password: <password>
# proxmox_node: node1                        # only this node (default: all)
# proxmox_skip_tls_verify: true              # self-signed certificate
```

### libvirt

```bash
sudo usermod -aG libvirt netwarden
sudo systemctl restart netwarden
virsh -c qemu:///system list --all           # verify access
```

```yaml
enable_vms: true
vm_hypervisor: libvirt
# libvirt_uri: qemu:///system                # default
# libvirt_uri: qemu+ssh://user@host/system   # remote host
# libvirt_socket: /var/run/libvirt/libvirt-sock   # non-default local socket
```

`libvirt_socket` applies only to a local URI that does not already name a
socket.

### VM options

```yaml
enable_vms: true                             # on by default; inactive without a hypervisor
vm_hypervisor: auto                          # auto, proxmox, libvirt, kvm, xen, qemu

# Name globs, comma-separated. An exclude match always wins.
# vm_include: prod-*,db-*
# vm_exclude: test-*,dev-*

# vm_stats_interval: 120                     # seconds
# vm_timeout: 30                             # seconds per hypervisor operation
# vm_cache_timeout: 300                      # seconds the VM list is reused
# vm_parallel_stats: 5                       # VMs queried for stats at once
```

### What is reported per VM

Every series carries `vm`, `vm_id`, `hypervisor` and `os_type` labels (plus
`node` and `vmid` on Proxmox). The "any" rows are reported by every libvirt
since 1.2 and by Proxmox. Other series appear only when the hypervisor reports
them; a missing value is a gap, not a zero. `vm_status` is 0 stopped,
1 running, 2 paused.

| Group | Series | Needs |
|---|---|---|
| Inventory | `vm_status`, `vm_cpu_count`, `vm_memory_mb`, `vm_disk_gb`, `vm_vcpu_current` | any |
| CPU | `vm_cpu_usage_percent` (of the VM's vCPUs), `vm_cpu_time_seconds`, `vm_cpu_user_seconds`, `vm_cpu_system_seconds` | utilisation needs two observations |
| vCPU scheduling | `vm_vcpu_wait_seconds` (steal), `vm_vcpu_delay_seconds` | libvirt; delay needs 7.3+ |
| Memory, host view | `vm_memory_usage_mb`, `vm_memory_available_mb`, `vm_memory_usage_percent` | any |
| Memory, guest view | `vm_guest_memory_total_mb`, `vm_guest_memory_used_mb`, `vm_guest_memory_usage_percent`, `vm_memory_swap_in_kb`, `vm_memory_swap_out_kb`, `vm_memory_major_faults`, `vm_memory_minor_faults` | virtio-balloon with stats (libvirt) or the QEMU guest agent (Proxmox) |
| Disk I/O | `vm_disk_read_bytes`, `vm_disk_write_bytes`, `vm_disk_read_ops`, `vm_disk_write_ops`, `vm_disk_flush_ops`, `vm_disk_read_time_seconds`, `vm_disk_write_time_seconds`, `vm_disk_flush_time_seconds` | timings: libvirt |
| Disk space | `vm_disk_allocation_bytes`, `vm_disk_capacity_bytes`, `vm_disk_usage_percent` | libvirt; Proxmox containers |
| Network | `vm_network_rx_bytes`, `vm_network_tx_bytes`, `vm_network_rx_packets`, `vm_network_tx_packets`, `vm_network_rx_errors`, `vm_network_tx_errors`, `vm_network_rx_dropped`, `vm_network_tx_dropped` | any |
| Migration | `vm_dirty_rate_mb_per_second` | libvirt 7.2+, after `virsh domdirtyrate-calc` |
| Uptime | `vm_uptime_seconds` | Proxmox |
| Guest OS | `vm_guest_info` (OS, kernel, hostname as labels), `vm_guest_users_count`, `vm_guest_load1/5/15`, `vm_fs_total_bytes`, `vm_fs_used_bytes`, `vm_fs_usage_percent` (per mountpoint) | a guest agent in the VM; libvirt 5.7+ (load: 9.2+) |

Guest-agent reports are refreshed every five minutes per VM. A VM without an
agent is remembered as such for the same period, so it costs only its
`domstats` call.

### Troubleshooting

```bash
grep -i vm /var/log/netwarden/netwarden.log
curl -k https://proxmox.example.com:8006/api2/json/version   # Proxmox API reachable?
virsh list --all                                             # libvirt access?
```

- Permission denied: add the agent's user to the `libvirt` (or `qemu`) group.
- No VMs on Proxmox: check that `proxmox_api` and credentials are set.
- High CPU on large hosts: raise `vm_stats_interval` or lower `vm_parallel_stats`.

Use read-only accounts and API tokens, keep hypervisor APIs on private
networks, and leave TLS verification on in production.

## Service Management

```bash
sudo systemctl start netwarden
sudo systemctl stop netwarden
sudo systemctl restart netwarden
sudo systemctl enable netwarden
sudo systemctl status netwarden

sudo journalctl -u netwarden -n 50
sudo journalctl -u netwarden -f
sudo tail -f /var/log/netwarden/netwarden.log

netwarden --version
```

On FreeBSD use `service netwarden start|stop|restart|status`.

---

## Developer Documentation

### Architecture

One process, one loop. Every reporting interval the agent runs its collectors
concurrently (at most three at a time, each with a 10 s timeout), passes the
metrics through the delta filter, and POSTs the remainder, with any snapshots
the cycle produced, to `/agent/data` in batches of up to 500.

```
  collectors (cpu, memory, disk, network, system, container, vm, k8s,
              mysql, postgresql, process, security_*, cis, fim, opnsense)
        │  Collect(ctx): concurrent, bounded, per-collector timeout
        ▼
  registry.CollectAll ──► metrics + snapshots for this cycle
        │
        ▼
  DeltaTracker.FilterMetrics: drop gauges that moved < 1% and were sent
                              within the last 5 minutes; counters and
                              first sightings always pass
        │
        ▼
  HTTPTransmitter.Send: batches of 500, snapshots (device_identity, spool)
                        on the first batch, retries, 429 honoured,
                        backoff after repeated failure
        │
        ▼
  POST {server_url}/agent/data
```

Slow or expensive sources run on their own schedule and are cached: OS update
checks and the package inventory every 6 hours, listening sockets every
5 minutes, sshd config, CIS and FIM hourly. The collection loop itself reads
only cheap sources (procfs, sysfs, the container and hypervisor APIs) and the
caches.

### Project structure

```
agent/
├── cmd/netwarden/
│   ├── main.go                 # entry point, flags, logging, signal handling
│   ├── main_windows.go         # Windows service integration
│   ├── main_nonwindows.go
│   └── logfile*.go             # log file, reopened on SIGHUP
│
├── internal/
│   ├── agent/
│   │   ├── agent.go            # collector registration, remote config, the loop
│   │   ├── transmitter.go      # /agent/data client: payload, retries, backoff
│   │   ├── collectors_security.go
│   │   ├── collectors_linux.go / collectors_nonlinux.go   # VM collector gating
│   │   ├── extras.go           # device_identity and spool snapshots per post
│   │   ├── snapshot_ack.go     # snapshots held until the platform acknowledges them
│   │   └── state.go            # state.json for local producers
│   │
│   ├── collectors/
│   │   ├── cpu/ memory/ disk/ network/ system/
│   │   ├── container/          # Docker / Podman, image inventory
│   │   ├── vm/                 # libvirt and Proxmox
│   │   ├── k8s/                # in-cluster watchers: health, jobs, CNPG, ingress
│   │   ├── opnsense/           # gateways, firmware, pf, IDS, logs, CARP
│   │   ├── mysql/ postgresql/
│   │   ├── process/            # UI-defined application processes
│   │   ├── security/           # failed logins, sshd config, ports, packages
│   │   ├── cis/                # CIS benchmark evaluation
│   │   └── fim/                # file integrity monitoring
│   │
│   ├── metrics/                # Metric, Snapshot, Collector interfaces; delta filter
│   ├── registry/               # runs one collection cycle
│   ├── config/                 # netwarden.conf parsing and validation
│   ├── identity/               # device_identity snapshot
│   ├── spool/                  # local producers' spool (docs/spool.md)
│   ├── selfupdate/             # signed self-update
│   ├── winsec/                 # Windows security descriptor checks
│   ├── http/                   # shared HTTP client and TLS settings
│   ├── resilience/             # retry with permanent-error short-circuit
│   └── cache/                  # small TTL cache for slow sources
│
├── docs/spool.md               # spool and state.json contract
├── Makefile
├── go.mod / go.sum
├── VERSION
└── CHANGELOG.md
```

Packaging (deb, rpm, the FreeBSD package, install scripts, the systemd unit
and logrotate config) lives outside this repository. Released packages are
published at https://get.netwarden.com.

### Collectors

```go
type Collector interface {
    Name() string                                    // unique name
    Collect(ctx context.Context) ([]Metric, error)   // one cycle's metrics
    Enabled() bool                                   // false = skipped this cycle
    Close() error                                    // release resources
}
```

A collector that also implements `SnapshotProvider` can stage a structured
document (an sshd audit, the socket table, the package inventory) during
`Collect`. The registry drains it after the cycle and the transmitter sends it
with the metrics. One collector failing or timing out does not affect the
others, and its results from earlier cycles are never replayed.

### Registry

`registry.CollectAll` runs every enabled collector for one cycle with bounded
parallelism and a per-collector timeout, and returns the combined metrics plus
an error naming any collector that failed. Each call owns its goroutines and
results. A collector that ignores cancellation is not started again until its
previous run returns.

### Delta tracker

A gauge is sent when it moves at least 1% from the last value sent, or when
5 minutes have passed since it was last sent. Counters are sent whenever they
increase, and a metric seen for the first time is always sent. State for
metrics not seen in 24 hours is dropped hourly.

### Transmitter

`HTTPTransmitter` builds the `/agent/data` payload and retries failed sends.
It honours `Retry-After` on 429 (capped at five minutes), retries 408 and 425,
and treats 401 and other 4xx responses as permanent. After three consecutive
failed cycles it backs off, from 30 s doubling to a 5-minute cap.

### Building from source

Requirements: Go 1.27 or later (see `go.mod`). Make is optional.

```bash
git clone https://github.com/NetwardenHQ/agent
cd agent

# Current platform, with version, date and commit stamped in; output in bin/
make build

# Plain go
go build -o netwarden ./cmd/netwarden

# Plain go with version information
go build -ldflags "-X main.version=$(cat VERSION) -X main.buildDate=$(date -u '+%Y-%m-%d_%H:%M:%S') -X main.gitCommit=$(git rev-parse --short HEAD)" -o netwarden ./cmd/netwarden

# Cross-compile
GOOS=linux GOARCH=arm64 go build -o netwarden-linux-arm64 ./cmd/netwarden
GOOS=freebsd GOARCH=amd64 go build -o netwarden-freebsd-amd64 ./cmd/netwarden
GOOS=windows GOARCH=amd64 go build -o netwarden-windows-amd64.exe ./cmd/netwarden

# Every supported platform into bin/
make build-all
```

The package build (deb, rpm, FreeBSD `.pkg`, Windows installer) is not part of
this repository. `make build-all` produces the binaries those packages wrap.

### Testing

```bash
go test ./...
go test -race ./...
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
go test -v ./internal/collectors/cpu
```

### Measuring footprint

The agent has no profiling endpoint. To measure it, point a build at a stub
server and read `/proc`:

```bash
make build
./bin/netwarden -c /path/to/test.conf &      # server_url set to a local stub
PID=$!
grep -E 'VmRSS|VmHWM|Threads' /proc/$PID/status
awk '{print ($14+$15)/100 " CPU seconds"}' /proc/$PID/stat
```

For hot-path work use `go test -bench` and `go tool pprof` on the package in
question.

## Security

Report vulnerabilities privately to security@netwarden.com. See
[SECURITY.md](SECURITY.md).

- The agent opens no listening ports. It makes outbound HTTPS requests to `server_url` only (plus the local database, hypervisor and container APIs you configure).
- TLS certificates are verified unless `tls_skip_verify` is set. `tls_ca_cert` adds a private CA.
- Some sources need root: the OPNsense collector, and CIS checks against `/etc/shadow` and `/etc/sudoers` (or `CAP_DAC_READ_SEARCH`). Unprivileged, those CIS checks report `error` instead of a result.
- Files read with elevated privileges are opened without following symlinks and checked on the open descriptor.
- Self-updates are verified against pinned signing keys that only the local config can change: the Authenticode signature on Windows, the release signature on macOS and FreeBSD, and the signed apt/yum repository on Linux packages.

Recommendations:

1. Keep `netwarden.conf` at mode `0600`, owned by root or the agent's user.
2. Use dedicated, read-only accounts for databases and hypervisors.
3. Rotate API keys periodically.
4. Keep the agent up to date.

## Troubleshooting

### Agent will not start

The agent exits with a message when:

- `tenant_id` is missing or not exactly 10 characters,
- `api_key` is missing or does not start with `nw_sk_`,
- `server_url` does not start with `http://` or `https://`,
- the config file does not exist at the given or default path.

### No metrics in the dashboard

```bash
curl -I https://api.netwarden.com
journalctl -u netwarden -n 100 | grep -i error
grep -E '^(tenant_id|api_key|server_url)' /etc/netwarden/netwarden.conf
```

A 401 in the log means the `tenant_id` or `api_key` is wrong.

### Reducing load

The reporting interval is set by the platform. To reduce work on a busy host,
turn off collectors you do not need:

```yaml
enable_containers: false
enable_vms: false
enable_security_lang_packages: false
enable_fim_realtime: false
```

### Debug logging

```bash
sudo systemctl stop netwarden
# set log_level: debug in netwarden.conf
sudo netwarden --config /etc/netwarden/netwarden.conf
```

### Database connection failures

```bash
psql -h localhost -U svc_netwarden -d postgres -c "SELECT 1"
mysql -h localhost -u svc_netwarden -p -e "SELECT 1"
ls -la /var/run/postgresql/.s.PGSQL.5432 /var/run/mysqld/mysqld.sock
```

## Contributing

```bash
git clone https://github.com/YOUR_USERNAME/agent
cd agent
go mod download
make test
make build
```

Fork the repository, create a branch, and open a pull request against `master`.
Run `go test ./...` and `go vet ./...` before submitting.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Support

- Email: support@netwarden.com
- Issues: [GitHub Issues](https://github.com/NetwardenHQ/agent/issues)
- Documentation: [netwarden.com/docs](https://netwarden.com/docs)
