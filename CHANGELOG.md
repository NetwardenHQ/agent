# Changelog

All notable changes to the Netwarden Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-05

### Added

- **Self-hosted server support** — The agent now works with both Netwarden SaaS and self-hosted
  deployments. Users can point the agent at any Netwarden server by setting `server_url` in the
  config file. Defaults to the SaaS API (`https://api.netwarden.com`) for backward compatibility.

- **Custom TLS configuration** — Two new config options for self-hosted deployments with
  self-signed or internal CA certificates:
  - `tls_skip_verify` — Disables TLS certificate verification (for development/testing only).
  - `tls_ca_cert` — Path to a custom CA certificate file (PEM format) for trusting internal CAs.

- **Startup connection test** — On launch, the agent performs a non-blocking connectivity check
  against the configured server. Logs clear messages for success, authentication failure, or
  connection errors with actionable hints (check `server_url`, credentials, TLS settings).

### Fixed

- **Config parsing ignores user-disabled collectors** — `LoadConfig()` unconditionally set all
  collector toggles to `true` after parsing the config file, making it impossible for users to
  disable collectors via `enable_disk: false` etc. Defaults are now applied before config file
  parsing so user values take precedence.

- **PostgreSQL database stats never collected** — `getDatabaseStats()` queried `n_live_tup` and
  `n_dead_tup` from `pg_stat_database`, but those columns only exist in `pg_stat_user_tables`.
  Every call to this function returned an error. Removed the invalid columns and added a separate
  aggregation query against `pg_stat_user_tables`.

- **Agent crash on containers with empty Names** — Accessing `Names[0]` without a bounds check
  caused a panic if the Docker/Podman API returned a container with an empty Names slice. Added
  bounds check with fallback to truncated container ID.

- **VM collector goroutine leak on context cancellation** — `break` inside a `select` only exited
  the `select`, not the `for` loop. Goroutines launched without a `WaitGroup` could accumulate
  across collection cycles. Added labeled break, `sync.WaitGroup`, and proper channel close.

- **Process name regex injection via pgrep** — API-provided process names were passed unsanitized
  to `pgrep -f`, which interprets the argument as a regex. A crafted name could cause ReDoS or
  match unintended processes. Now escaped with `regexp.QuoteMeta()`.

- **WMI query injection on Windows** — API-provided process names were interpolated directly into
  WQL queries without escaping single quotes. Added `sanitizeWQLString()` to both the primary
  and retry query paths.

- **Agent crash on short container IDs** — `container.ID[:12]` had no bounds check, risking a
  panic if the ID was shorter than 12 characters. Added safe slicing.

- **Process config endpoint path** — Default process monitoring endpoint was `/agent-config/processes`
  but the server expects `/agent/processes`. Fixed the default in validation.

- **Missing version field in Agent struct** — `testConnection()` referenced `a.version` but the
  field was never stored. Added `version` field to the Agent struct and set it in the constructor.

### Updated

- `github.com/lib/pq` v1.10.9 -> v1.11.2
- `github.com/shirou/gopsutil/v4` v4.25.8 -> v4.26.2
- `golang.org/x/net` v0.38.0 -> v0.51.0
- `golang.org/x/sys` v0.36.0 -> v0.41.0
- `github.com/ebitengine/purego` v0.9.0 -> v0.10.0
- `github.com/tklauser/go-sysconf` v0.3.15 -> v0.3.16
- `github.com/tklauser/numcpus` v0.10.0 -> v0.11.0

## [1.0.0] - 2025-01-20

### Initial Public Release

Enterprise-grade infrastructure monitoring agent with comprehensive monitoring capabilities and minimal resource footprint.

#### Core Features
- **High Performance** - Minimal CPU (<1%) and memory (<50MB) footprint
- **Secure by Design** - Runs as non-root, encrypted communications, secure token authentication
- **Zero Dependencies** - Single static binary with no runtime dependencies
- **Multi-Platform Support** - Linux, Windows, macOS on AMD64, ARM64, and ARMv7 architectures

#### Monitoring Capabilities
- **System Monitoring** - CPU, memory, disk, network, load average, processes
- **Container Monitoring** - Docker, Podman, and Kubernetes support with per-container metrics
- **Database Monitoring** - PostgreSQL and MySQL/MariaDB health checks and performance metrics
- **VM Monitoring** - Libvirt and Proxmox virtual machine metrics
- **Process Monitoring** - Top processes by CPU and memory usage
- **Update Detection** - Package manager update tracking for security and system updates

#### Performance & Reliability
- **Smart Data Compression** - Delta compression and adaptive batching reduce bandwidth by 90%
- **Circuit Breakers** - Automatic failure detection and recovery
- **Graceful Degradation** - Continues operating even when individual collectors fail
- **Automatic Retries** - Exponential backoff for failed API requests
- **Connection Pooling** - Efficient HTTP client with keep-alive connections

#### Installation Methods
- One-line automatic installation script
- Native package managers (APT, YUM/DNF)
- Direct binary downloads for all platforms
- Systemd service integration on Linux
- Windows service support
- macOS launchd support

#### Security Features
- Non-root execution (drops privileges after startup)
- Encrypted API communications (HTTPS/TLS)
- Secure API key authentication
- Minimal attack surface (single binary, no dependencies)
- Apache 2.0 open source license

[2.0.0]: https://github.com/netwardenhq/agent/releases/tag/v2.0.0
[1.0.0]: https://github.com/netwardenhq/agent/releases/tag/v1.0.0
