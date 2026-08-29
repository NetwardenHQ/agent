package agent

import (
	"log/slog"

	"netwarden/internal/collectors/cis"
	"netwarden/internal/collectors/security"
	"netwarden/internal/metrics"
)

// registerSecurityCollectors wires up the security-posture collectors on every
// platform. Each collector reports its own Enabled() based on whether the
// current OS has an implementation, and the registry skips disabled ones — so
// registering unconditionally here is safe and keeps the platform matrix in
// one place (the collector) rather than split across registration sites.
//
// Coverage as of this revision:
//
//	security_ports      Linux (ss/netstat), macOS + Windows (gopsutil)
//	security_sshconfig  Linux, macOS, Windows (OpenSSH config syntax is shared)
//	security_auth       Linux only (journald / auth.log / secure)
//	security_packages   Linux only (dpkg / rpm)
//	cis                 Linux only, and only once a profile is defined in the UI
//
// Registration failures are logged and skipped rather than aborting agent
// startup: losing a posture collector should never take resource monitoring
// down with it.
func (a *Agent) registerSecurityCollectors(collectorLogger *slog.Logger) {
	if a.config.Collectors.SecurityAuth {
		c := security.NewAuthCollector(
			a.hostname,
			security.WithAuthLogger(collectorLogger.With("type", "security_auth")),
		)
		a.registerSecurityCollector("security_auth", c)
	}

	if a.config.Collectors.SecuritySSHConfig {
		c := security.NewSSHConfigCollector(
			a.hostname,
			security.WithSSHConfigLogger(collectorLogger.With("type", "security_sshconfig")),
		)
		a.registerSecurityCollector("security_sshconfig", c)
	}

	if a.config.Collectors.SecurityPorts {
		c := security.NewPortsCollector(
			a.hostname,
			security.WithPortsLogger(collectorLogger.With("type", "security_ports")),
		)
		a.registerSecurityCollector("security_ports", c)
	}

	if a.config.Collectors.CIS {
		c := cis.NewCollector(
			a.hostname,
			cis.WithLogger(collectorLogger.With("type", "cis")),
		)
		a.cisCollector = c
		a.registerSecurityCollector("cis", c)
	}

	if a.config.Collectors.SecurityPackages {
		c := security.NewPackagesCollector(
			a.hostname,
			security.WithPackagesLogger(collectorLogger.With("type", "security_packages")),
		)
		a.registerSecurityCollector("security_packages", c)
	}
}

// registerSecurityCollector registers one collector, logging rather than
// failing when registration is rejected (duplicate name, nil collector).
func (a *Agent) registerSecurityCollector(name string, c metrics.Collector) {
	if err := a.registry.Register(c); err != nil {
		a.logger.Warn("failed to register security collector", "name", name, "error", err)
		return
	}
	if c.Enabled() {
		a.logger.Info("registered security collector", "name", name)
	} else {
		a.logger.Debug("security collector registered but inactive on this platform", "name", name)
	}
}
