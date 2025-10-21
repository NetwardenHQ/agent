//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log/slog"
	"netwarden/internal/collectors/vm"
)

// registerVMCollector registers the VM collector on Linux systems only.
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
	return nil
}
