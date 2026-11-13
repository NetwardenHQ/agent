//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log/slog"

	"github.com/NetwardenHQ/agent/internal/collectors/synology"
	"github.com/NetwardenHQ/agent/internal/collectors/vm"
)

// registerVMCollector registers the VM collector on Linux systems only.
// Security-posture collectors are registered separately and on every platform
// by registerSecurityCollectors (collectors_security.go).
func (a *Agent) registerVMCollector(collectorLogger *slog.Logger) error {
	if a.config.Collectors.VM {
		vmCollector := vm.NewCollector(
			a.config.VM,
			a.hostname,
			vm.WithLogger(collectorLogger.With("type", "vm")),
		)
		if err := a.registry.Register(vmCollector); err != nil {
			return fmt.Errorf("failed to register VM collector: %w", err)
		}
		a.logger.Info("registered VM collector")
	}

	// Synology DSM. Inactive on any other Linux host.
	if a.config.Collectors.Synology {
		c := synology.NewCollector(
			a.hostname,
			synology.WithLogger(collectorLogger.With("type", "synology")),
			synology.WithStatusDir(a.config.SynologyStatusDir),
		)
		if err := a.registry.Register(c); err != nil {
			return fmt.Errorf("failed to register Synology collector: %w", err)
		}
	}

	return nil
}
