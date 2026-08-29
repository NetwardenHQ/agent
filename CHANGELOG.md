# Changelog

All notable changes to the Netwarden Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0-beta] - 2026-08-29

### Added

- **CIS Benchmark evaluation** — The agent evaluates the CIS profile an operator defines in the
  Netwarden UI. 228 checks for CIS Red Hat Enterprise Linux 9 (Level 1: 154, Level 2: 74) across
  all seven benchmark sections, evaluated via 18 compiled inspection primitives.

  The catalog is **compiled into the agent**. The server selects which checks run, by id, and may
  override expected values — it never supplies a file path, sysctl key, command, or regex. A
  compromised control plane can turn checks on and off and make them report wrongly; it cannot make
  an agent read an arbitrary file or execute an arbitrary command. `TestProfileCannotAlterProbeTargets`
  pins that property. Command execution is separately restricted to `systemctl`, `rpm` and
  `auditctl` with constant arguments.

  Results distinguish five statuses. `error` (the agent could not evaluate the check — typically an
  unreadable file when running unprivileged) is deliberately neither pass nor fail, and is excluded
  from the compliance score: counting it as a failure would make the score drop whenever the agent
  loses a permission. Waived checks are still evaluated so the UI can show real state, and carry
  their underlying verdict.

  Off by default. Requires both `enable_cis` in the config file and a profile defined in the UI.
  Runs hourly, and immediately when the profile revision changes. Linux only.

  **Privileges:** running unprivileged, checks against `/etc/shadow` and `/etc/sudoers` report as
  `error` rather than being evaluated. Full coverage needs root or `CAP_DAC_READ_SEARCH`.

- **Package ecosystem identifiers** — Every entry in the `installed_packages` snapshot now carries
  an `ecosystem` field alongside `source`. `source` is the tool that reported the package (`dpkg`,
  `rpm`); `ecosystem` is the namespace that decides which vulnerability feed applies (`deb`,
  `rpm`). The distinction lets the platform route OS packages to the distro advisory feeds and,
  once host-installed language packages are collected, route those to OSV instead. The language
  ecosystem identifiers (`npm`, `pypi`, `rubygems`, `gomod`, `cargo`, `maven`, `nuget`,
  `composer`) are defined and match the platform's OSV ecosystem union verbatim, but nothing
  emits them yet.

  This is additive: the platform treats an absent `ecosystem` as an OS package, so agents at
  2.1.0 and earlier continue to match against distro advisories unchanged.

### Changed

- **Windows binaries are now signed by Moriah LLC** — Authenticode signing moved from the
  Netwarden LLC certificate to the Moriah LLC code-signing certificate, the same key used for
  Epistles. Windows will show "Moriah LLC" as the publisher on the agent installer and
  executables. The signing key itself never leaves the YubiKey; only the certificate changed.
  Linux package (GPG) signing is unaffected and continues to use the
  `Netwarden Package Signing <packages@netwarden.com>` key, so `apt`/`dnf` clients need no action.

### Tests

- dpkg and rpm output parsers, including ecosystem assignment and malformed-row handling.

## [2.1.0] - 2026-08-28

### Added

- **Structured security snapshots** — The agent now emits a top-level `snapshots` array in the
  `/agent/data` payload, carrying `ssh_config`, `listening_ports`, and `installed_packages` in the
  shapes the platform's findings evaluator and CVE matcher consume. Previously these payloads were
  JSON-encoded into metric *label* values, which nothing server-side read, so the entire host
  security findings pipeline received no input.

- **macOS and Windows security coverage** — The listening-port audit now runs on macOS and Windows
  via gopsutil (lsof on Darwin, GetExtendedTcpTable/GetExtendedUdpTable on Windows), and the SSH
  configuration audit runs on macOS and on the Windows OpenSSH server (`%ProgramData%\ssh\sshd_config`).
  Exposure scoring is shared across all platforms, so a public bind on a management port is judged
  identically everywhere. Failed-login and package-inventory collection remain Linux-only.

- **Per-collector security toggles** — `enable_security_auth`, `enable_security_sshconfig`,
  `enable_security_ports`, `enable_security_packages`, and the `enable_security` master switch.
  All default to on. These collectors read authentication logs, the sshd configuration, the
  listening socket table, and the package database, so each can now be disabled independently.

- **Config file permission check** — On startup the agent warns when `netwarden.conf` is readable
  or writable beyond its owner. The file holds the `nw_sk_*` API key and any configured
  Proxmox/MySQL/PostgreSQL passwords in cleartext. Non-fatal by design so an existing fleet does
  not go dark on upgrade.

- **First test suite** — Table-driven tests covering the `ss`/`netstat` parsers, bind-address
  classification, sshd_config snapshot conversion, config permission handling, and the wire
  payload contract against the server's Zod schema.

### Fixed

- **`ss` fallback silently reported zero open ports** — When `ss -tulnpH` failed, the agent fell
  back to `ss -tlnpH`. Requesting a single socket family makes `ss` omit the `Netid` column, so
  every row began with `LISTEN` rather than `tcp` and the parser skipped all of them. The fallback
  returned an empty socket set with no error, and the host reported `security_open_ports_count = 0`
  — a false all-clear on a host that may have had exposed management ports. The parser now handles
  both column layouts, and a source that yields no sockets is treated as a failure that falls
  through to the next source rather than an authoritative zero.

- **Interface-bound wildcard addresses fell out of both counters** — Bind addresses carrying a
  kernel zone suffix (`0.0.0.0%virbr0` for SO_BINDTODEVICE sockets, `fe80::1%eth0` for IPv6
  link-local) matched neither the public nor the loopback classifier, so they were missing from
  `security_public_bind_count`. Observed live on a host running libvirt.

- **Package inventory re-sent every reporting interval** — `PackagesCollectionInterval` (6h) was
  declared but never applied; the full dpkg/rpm inventory was re-enumerated and re-transmitted
  every cycle. On a 1,454-package host that is ~135KB per minute of near-identical data. The
  inventory now honours its interval, with cached gauges re-emitted between runs so the time
  series stays continuous. Measured steady-state payload dropped from ~138KB to ~2.8KB per cycle.

- **`tcp6`/`udp6` rows from `netstat` used a non-contract protocol value** — Now normalized to
  `tcp`/`udp`, which is all the platform contract accepts.

### Changed

- **Go 1.27.0** (from 1.25.1), picking up roughly fifty stdlib security fixes released in the
  interim. `govulncheck` reports no known vulnerabilities.

- **Dependencies upgraded** — `golang.org/x/sys` v0.42.0 → v0.47.0 (addresses GO-2026-5024),
  `golang.org/x/net` v0.52.0 → v0.58.0, `gopsutil/v4` v4.26.2 → v4.26.7,
  `go-sql-driver/mysql` v1.9.3 → v1.10.0, `lib/pq` v1.11.2 → v1.12.3,
  `jackpal/gateway` v1.1.1 → v1.2.0, plus transitive updates.

- Socket exposure classification is now shared by all platform implementations rather than
  duplicated per platform.

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
