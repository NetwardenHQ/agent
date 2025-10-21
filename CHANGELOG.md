# Changelog

All notable changes to the Netwarden Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/netwardenhq/agent/releases/tag/v1.0.0
