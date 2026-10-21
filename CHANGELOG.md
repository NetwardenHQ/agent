# Changelog

All notable changes to the Netwarden Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Kubernetes: the CronJob report carries each job's `time_zone` (spec.timeZone), so the dashboard
  can recompute the next run from the schedule once the reported one has passed.
- Containers: per-container `container_state_<id>` (0 created, 1 running, 2 paused, 3 restarting,
  4 exited, 5 dead, 6 removing, -1 unknown), `container_health_<id>` (1 healthy, 0 unhealthy,
  2 starting; only for containers with a health check), `container_exit_code_<id>` for stopped
  containers, and `container_restarts_<id>` where the runtime lists it (Podman).
- MySQL and PostgreSQL: `*_max_connections` and `*_connections_used_percent`. PostgreSQL counts
  client backends only, the ones `max_connections` limits.
- `security_auth_log_readable`: 1 when the failed-login collector read journald or a syslog file,
  0 when it could read neither.

### Fixed
- Failed logins were undercounted on hosts collecting less often than once a minute: the
  collector looked back a fixed 60 seconds. It now counts the events since the previous
  collection, at any interval, with a single look-back capped at one hour.
- Failed logins read from `/var/log/auth.log` or `/var/log/secure` were counted again on every
  collection while they stayed in the tail of the file. Each line is placed by its own timestamp,
  in RFC 3339 or traditional syslog format.
- A host whose login sources were unreadable reported 0 failed logins. It reports
  `security_auth_log_readable 0` and no counts instead.
- The Docker-compatible socket client listed running containers only, so a stopped or crashed
  container disappeared from the report instead of showing as exited.
- MySQL and PostgreSQL went silent when the server stopped or refused the agent: the collector
  disabled itself whenever its ping failed. A configured or detected server keeps reporting
  `*_up`, and `*_connection_failed` is 1 while the agent cannot connect and 0 once it can.

## [3.1.2] - 2026-10-20

### Fixed
- Kubernetes: a failed Job kept as CronJob history (`failedJobsHistoryLimit`) no longer marks
  the CronJob degraded once a later run has finished. The most recent finished run decides, so
  `k8s_workloads_degraded`, `k8s_jobs_failing` and the related findings clear when the CronJob
  recovers rather than when Kubernetes prunes the failed run.

## [3.1.1] - 2026-10-18

### Fixed
- SSH server posture on OPNsense and on FreeBSD hosts running the openssh-portable port: the
  agent reads `/usr/local/etc/ssh/sshd_config` when `/usr/local/sbin/sshd` is installed,
  rather than skipping the checks because the base `/etc/ssh/sshd_config` does not exist.

## [3.1.0] - 2026-10-18

### Added
- OPNsense collector (`enable_opnsense`, on by default, inactive on other hosts): gateway
  health, firmware and package updates, pf state table, Suricata IDS/IPS, filter log, GUI and
  SSH logins from the audit log, CARP and configuration changes. Read-only.
- FreeBSD 14 and 15 support on amd64 and arm64, shipped as `netwarden-agent-<version>.pkg` with
  an rc.d script supervised by `daemon(8)` and a newsyslog rule. FreeBSD also reports `pkg`
  update counts, listening ports via `sockstat`, and has its own file-integrity ruleset.
- The log file is reopened on SIGHUP, so rotation by renaming (newsyslog, logrotate without
  `copytruncate`) works.
- `device_identity` snapshot every cycle: role, platform and version, vendor, capabilities, and
  interfaces with CIDR addresses and MAC.
- Spool reader for local producers (`spool_dir`): events, network exposure and identity files.
  The format is documented in [docs/spool.md](docs/spool.md).
- `state.json`, written at startup and after every post attempt, so local producers can tell
  whether the agent is running and delivering.
- `self_update_signers` accepts `spki-sha256:` (public key) and `sha256:` (certificate) pins
  in addition to a certificate CN.
- `libvirt_socket` is now honored.
- The language package inventory reports when it was truncated by its scan limits.

### Changed
- FIM real-time watching is off by default on macOS and FreeBSD, where kqueue needs one open
  descriptor per watched file. Set `enable_fim_realtime: true` to turn it on.
- ZFS disk usage is reported once per pool, from the root dataset's used and available bytes
  (usable capacity, net of parity), on every OS. Datasets with a `quota` or `refquota` keep
  their own series.
- Container CPU% uses one scale, 100 = one core, for both the Docker/Podman API and the
  podman CLI.
- Paused VMs report `vm_status` 2.
- The OPNsense config-change user and description are labels on
  `opnsense_config_last_change_timestamp`.
- Kubernetes targets are namespace-qualified (`namespace/Kind/name`). Open findings are
  re-keyed once after the upgrade.
- Kubernetes watches resume from the last `resourceVersion` instead of re-listing.
- PostgreSQL connects with `sslmode=prefer` and MySQL with `tls=preferred` to remote hosts.
  Unix sockets and loopback stay plaintext.
- Config values may carry a trailing `# comment` and may be quoted.
- `--create-config` refuses to overwrite an existing file.

### Fixed
- FIM: a walk that timed out was saved as a full baseline and then reported deletions and
  creations. It is now discarded.
- FIM: real-time watching of a single-file root no longer reports changes to its siblings.
- FIM: changes are kept until the platform acknowledges them, so a failed post loses nothing.
- FIM: file size is compared, unreadable files are not reported as modified, and uid/gid 0
  is reported instead of omitted.
- Kubernetes: a partial store sync is no longer reported as zero pods or as resolved findings.
- Kubernetes: cron schedules with `7` for Sunday, day and month names, and `N/step` parse.
- CNPG and pooler values are not reported when their exporter is unreachable.
- Process CPU no longer spikes after a failed read.
- Containers and VMs report nothing, rather than 0, for values the runtime did not provide.
- Proxmox: authentication on the availability probe, and a race on the auth header.
- `sockstat` output parsing on FreeBSD.
- OPNsense IDS counters are absent, not 0, when Suricata omits them.
- Daily log lines written after midnight.
- The transmitter retries 408 and 425 and caps `Retry-After` at five minutes.
- `state.json` no longer records cycles skipped during backoff as post attempts.
- A collector that ignores cancellation is not restarted while it is still running.
- The build command in the README.

### Security
- OPNsense failed logins take the service from the syslog program field and the source
  address from the end of the line. A crafted username could previously spoof the address or
  hide an SSH failure.
- Files read as root (FIM, language manifests, OPNsense firmware status) are opened with
  `O_NOFOLLOW|O_NONBLOCK` and checked on the open descriptor. The spool is read through
  `os.Root`.
- Spool and FIM baseline trust checks: owner and DACL on Windows, the directory and its
  parents on Unix.
- Windows self-update: the installer's version must match the offer and be newer (no
  downgrade), the signer can be pinned by public key, and the download is held under an
  exclusive handle in a protected directory until it is installed.
- The log file is opened without following symlinks, created 0640, and no longer falls back
  to `/tmp`. When the log directory is unusable the agent logs to stderr.
- Prometheus exporter scrapes are size-capped and do not follow redirects.
- OPNsense `config.xml` parsing buffers text only for the elements it reads.

## [3.0.0] - 2026-09-20

### Added
- **File integrity monitoring** — A new opt-in `fim` collector baselines a tight, high-signal set of
  system paths (binaries, sudoers/PAM/sshd config, passwd/shadow, systemd units, cron) by SHA-256
  content hash plus mode and owner, then reports what changes. Hybrid design: an agent-side manifest
  gives cheap change detection, and a roll-up digest shipped each cycle lets the platform detect a
  manifest that was wiped or tampered (a reset surfaces as `baseline_rebuilt` with a fresh
  `manifest_id`, which the server raises as a finding). The manifest is the agent's first persistent
  state — stored `0600` in a dedicated dir, written atomically, permission-checked on load, and
  itself a watched path.

  Detection is two-tier: an hourly full walk (bounded — max files/entries/depth, never follows
  symlinks — the reconcile and catch-all) plus an fsnotify real-time layer (inotify/kqueue) that
  surfaces a change within seconds as a delta, with a bounded watch-descriptor budget and event
  coalescing. Server-side, a noise policy decides which changes become findings: credential and
  persistence paths always surface, while package-managed binary changes during a package-update
  window are suppressed (correlated against the host's own package inventory) — so a routine
  `apt upgrade` does not become a wall of criticals. FIM findings are sticky (never auto-resolved),
  since a file modification is a fact that does not un-happen when the baseline absorbs it.

  Hashing is SHA-256 (stdlib, FIPS-friendly, no third-party crypto dependency in the agent binary).
  Linux, macOS, and Windows (each with its own high-signal default ruleset — Unix cron/systemd/
  sudoers, or Windows scheduled tasks / startup / hosts / Group Policy); off by default
  (`enable_fim: true`; real-time on by default, `enable_fim_realtime: false` to disable).
- **Container image inventory** — The container collector now emits a `container_images` snapshot:
  the distinct images the host runs, deduplicated by content digest, with running/total counts so
  twenty replicas of one image report once. `ImageID` (the `sha256:` digest) is captured from the
  Docker/Podman API as the stable identity. Feeds the platform's image-scanning pipeline; the
  inventory itself raises no findings. Built from the container list already fetched for metrics,
  so it costs no extra runtime calls.
- **Host language-package discovery (SBOM phase 2)** — The installed-packages snapshot now includes
  packages installed directly by language package managers — pip into site-packages, npm into
  node_modules — tagged with their ecosystem (`pypi`, `npm`) so the platform routes them to OSV
  rather than the distro advisory feeds. These are invisible to dpkg/rpm and are where unpatched
  dependencies accumulate; they now also appear in the CycloneDX SBOM export as `pkg:pypi/…` /
  `pkg:npm/…` components. Python system site-packages are auto-discovered (bounded); npm
  node_modules is scanned only under operator-configured `language_package_roots`. The walk is
  fenced by hard caps (max packages, max directory entries, max depth, a wall-clock budget), never
  follows symlinks, and does not recurse nested node_modules — a partial inventory is acceptable,
  an agent pegging host I/O is not. Enabled by default; disable with `enable_security_lang_packages: false`.
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
- **Collection cycles are isolated** — The registry runs each cycle's collectors on their own
  goroutines (at most three at a time, 10 s each) and owns that cycle's results. The worker pool
  it replaces shared one result channel across cycles: a collector that outran the cycle
  deadline delivered its metrics into the *next* cycle, and every cycle after that shipped one
  stale result and left one of its own behind. A regression test now covers this.
- **CPU utilisation is measured over the whole interval** — `cpu_usage_percent` is derived from
  the CPU time accumulated since the previous cycle instead of a blocking 100 ms sample, so it
  no longer stalls the cycle and reflects the interval rather than a glimpse of it. Only the
  very first cycle takes a short (250 ms) sample.
- **Process CPU is a percentage now** — `process_cpu_percent_*` reported the process's cumulative
  CPU *seconds* since it started, a number that only ever grew. It is now utilisation over the
  reporting interval (100 = one full core), computed from consecutive observations of the same
  PID; the first observation after a (re)start reports no value rather than a fabricated one.
- **Process lookup no longer forks** — On Linux the process collector walks `/proc` for the
  command line instead of exec'ing `pgrep` once per monitored process per cycle. macOS and the
  BSDs go through gopsutil and now report memory and CPU (previously PID only). The initial
  process-list fetch moved out of the constructor so startup never blocks on the network.
- **Listening-socket enumeration runs every 5 minutes** — The ports collector exec'd `ss` and
  shipped the full socket table on *every* reporting interval, the agent's single largest
  recurring cost. It now enumerates on the cadence its own documentation promised, re-emitting
  the last gauges (fresh timestamps, no snapshot) in between.
- **Transmitter** — Typed payload instead of nested `map[string]interface{}`; latency tracked
  atomically (was an unsynchronised write/read); 401 and other 4xx responses are permanent and
  no longer retried three times; `Retry-After` waits respect cancellation. Failure tracking
  lives in one place instead of two counters that disagreed.
- **Startup and shutdown** — The 0–20 s startup jitter and the update-check delay honour
  SIGTERM; the interval change from the server uses `Ticker.Reset`; shutdown errors are joined
  rather than formatted into a string.
- **Config file** — `--create-config` writes an example documenting every key the parser
  reads (security, CIS, FIM, Kubernetes and TLS keys were undocumented; the process-monitoring
  and log-file defaults it described were wrong). `-c` and `--config` bind the same flag.
  A missing file is detected with `errors.Is(err, fs.ErrNotExist)` instead of string matching.
- **Windows service** — A failed `svc.Run` was silently reported as success because of a
  shadowed `err`; the service path is now a single `runPlatformService` with a stub on other
  platforms, which also removes a `runtime.GOOS` branch from `main`.
- **Kubernetes watches now have a lifetime** — Every watch asks the API server to end it after a
  random 5–10 minutes (`timeoutSeconds`, as client-go does) and expires client-side shortly after.
  Before, a connection that died silently — a NAT entry timing out, a node network blip — left the
  watch blocked forever with no events and no error: the store went stale, `k8s_api_reachable`
  dropped to 0, and since every other k8s metric is gated on it the whole cluster view vanished
  until the agent was restarted. Regression test included.
- **VM stats cover everything libvirt reports, old and new** — `virsh domstats` is parsed
  group by group and every group a given libvirt lacks is simply absent, never zero: the
  libvirt 1.2 baseline (cpu time, balloon, block and interface counters) and the groups added
  since — cpu user/system split, online vCPUs, vCPU wait (steal) and scheduler delay (7.3+),
  the guest's own memory accounting from the balloon driver (`available`/`unused`, or
  `usable` on newer drivers), swap and page-fault counters, disk flush ops and per-operation
  timings, image allocation/capacity/physical (so `vm_disk_usage_percent` exists), interface
  errors and drops, and the dirty-page rate (7.2+, only once a measurement has completed).
  When a guest agent answers, `virsh guestinfo` (5.7+) adds `vm_guest_info` (OS, kernel,
  hostname as labels), per-filesystem `vm_fs_*` series with the mountpoint as a label, logged-in
  users and, on libvirt 9.2+, guest load averages. The agent report is cached five minutes
  per VM — including "no agent" — so a VM without one costs nothing beyond `domstats`.
  Proxmox gains vCPU count, guest memory (via `freemem` when its agent runs) and container
  disk usage from the same status call. Every new series is optional on the wire: the platform
  shows a gap where a hypervisor cannot measure something, not a flat zero.
- **VM collector** — `vm_cpu_usage_percent` on libvirt was always 0: it read a `cpu.util` series
  `virsh domstats` does not produce. It is now derived from the change in `cpu.time` between
  observations, per vCPU. libvirt "uptime" was fabricated from CPU time and is no longer reported
  (virsh exposes none); memory now uses `balloon.rss` as usage and `balloon.maximum` as the
  ceiling instead of adding the two. Stats take one `virsh domstats` per VM per cycle instead of
  three execs (`domname`, `domstats`, `dominfo`), and Proxmox no longer re-lists the whole cluster
  for every VM (it addresses `/nodes/<node>/<qemu|lxc>/<vmid>` directly, so LXC guests work too).
  Hypervisor reachability is cached for a minute instead of exec'ing `virsh version` twice a cycle.
  An unreachable hypervisor or a failed list now reports nothing rather than zero-valued counts.
- **Container collector** — The runtime monitor is now locked (it was mutated from two goroutines);
  the runtime's `/version` answer is parsed once instead of requested twice; one availability cache
  instead of two stacked ones; a failed container list is an error, not a `container_running_count`
  of 0. The stats fan-out is a plain bounded WaitGroup instead of 40 lines of channel plumbing.
- **Windows binaries are signed by Moriah LLC** — Authenticode signing moved from the
  Netwarden LLC certificate to the Moriah LLC code-signing certificate. Windows shows
  "Moriah LLC" as the publisher on the agent installer and executables. Linux package (GPG)
  signing is unaffected and continues to use the
  `Netwarden Package Signing <packages@netwarden.com>` key, so `apt`/`dnf` clients need no action.
- **Dependencies** — gopsutil 4.26.8, go-sql-driver/mysql 1.10.1, golang.org/x/sys 0.48.0,
  golang.org/x/net 0.59.0, purego 0.11.0. `govulncheck` reports no known vulnerabilities.

### Removed
- Dead packages that no code imported: `internal/errors` (1.1k lines), `internal/security`
  (a command allow-list and token store), `internal/compression` (gzip the transmitter never
  used — the platform does not accept compressed bodies), `internal/collectors/pool`, the
  circuit breaker, `collectors.BaseCollector`, `config/validation.go`, and the `--daemon`
  fork that had no flag. Also the never-parsed `buffer` and `database_connections` config,
  the registry's `Unregister`/`GetStats`, the never-used PostgreSQL stats cache, and a handful
  of write-only struct fields. About 3,000 lines in total; `staticcheck` is clean on Linux.

### Tests
- dpkg and rpm output parsers, including ecosystem assignment and malformed-row handling.
- Registry: partial failure, bounded concurrency, and the cross-cycle result leak.
- Kubernetes: a silent watch expires and the reflector re-lists. libvirt: `domstats` parsing,
  CPU utilisation across observations and restarts, memory unit conversion.
- CPU busy-percent arithmetic; process CPU% across restarts; retry's permanent-error and
  cancellation behaviour. The suite runs clean under `-race`.

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

[3.1.0]: https://github.com/NetwardenHQ/agent/releases/tag/v3.1.0
[3.0.0]: https://github.com/NetwardenHQ/agent/releases/tag/v3.0.0
[2.1.0]: https://github.com/NetwardenHQ/agent/releases/tag/v2.1.0
[2.0.0]: https://github.com/NetwardenHQ/agent/releases/tag/v2.0.0
[1.0.0]: https://github.com/NetwardenHQ/agent/releases/tag/v1.0.0
