package agent

import (
	"log/slog"

	"github.com/NetwardenHQ/agent/internal/collectors/cis"
	"github.com/NetwardenHQ/agent/internal/collectors/fim"
	"github.com/NetwardenHQ/agent/internal/collectors/k8s"
	"github.com/NetwardenHQ/agent/internal/collectors/opnsense"
	"github.com/NetwardenHQ/agent/internal/collectors/security"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// registerSecurityCollectors wires up the security-posture collectors on every
// platform. Each collector reports its own Enabled() based on whether the
// current OS has an implementation, and the registry skips disabled ones, so
// registering unconditionally is safe and keeps the platform matrix in one
// place (the collector) rather than split across registration sites.
//
// Coverage:
//
//	security_ports      Linux (ss/netstat), macOS + Windows (gopsutil)
//	security_sshconfig  Linux, macOS, Windows (OpenSSH config syntax is shared)
//	security_auth       Linux (journald / auth.log / secure), Windows (Security event log)
//	security_packages   Linux only (dpkg / rpm)
//	cis                 Linux only, and only once a profile is defined in the UI
//	fim                 Linux, macOS, Windows, FreeBSD; credential files by default, binaries with enable_fim: true
//	opnsense            OPNsense firewalls only (inactive on any other host)
//
// Registration failures are logged and skipped rather than aborting agent
// startup: losing a posture collector should never take resource monitoring
// down with it.
func (a *Agent) registerSecurityCollectors(collectorLogger *slog.Logger) {
	if a.config.Collectors.SecurityAuth {
		c := security.NewAuthCollector(
			a.hostname,
			security.WithAuthLogger(collectorLogger.With("type", "security_auth")),
			// Logins and account changes go out as spool events; with the
			// spool off they are not recorded, and the collector says so.
			security.WithSpoolDir(a.config.SpoolDir),
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

	if fimWanted(a.config.Collectors.FIM, a.config.FIMExplicit, k8s.InCluster()) {
		opts := []fim.Option{
			fim.WithLogger(collectorLogger.With("type", "fim")),
			fim.WithRealtime(a.config.FIMRealtime),
			fim.WithScope(fim.Scope(a.config.FIMScope)),
		}
		if a.config.FIMManifestPath != "" {
			opts = append(opts, fim.WithManifestPath(a.config.FIMManifestPath))
		}
		if len(a.config.FIMRoots) > 0 {
			opts = append(opts, fim.WithRoots(a.config.FIMRoots))
		}
		a.registerSecurityCollector("fim", fim.NewCollector(a.hostname, opts...))
	}

	if a.config.Collectors.OPNsense {
		c := opnsense.NewCollector(
			a.hostname,
			opnsense.WithLogger(collectorLogger.With("type", "opnsense")),
		)
		a.opnsenseCollector = c
		a.registerSecurityCollector("opnsense", c)
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
			security.WithLangPackages(a.config.Collectors.SecurityLangPackages, a.config.LangPackageRoots),
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

// fimWanted decides whether FIM runs. It is on by default, but an agent
// inside a Kubernetes cluster would only be watching its own container
// image, so there it runs only when enable_fim asks for it.
func fimWanted(enabled, explicit, inCluster bool) bool {
	if !enabled {
		return false
	}
	return explicit || !inCluster
}
