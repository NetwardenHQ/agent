//go:build !linux
// +build !linux

package agent

import "log/slog"

// registerVMCollector is a no-op on non-Linux systems since VM monitoring is
// not supported. Security-posture collectors are registered on every platform
// by registerSecurityCollectors (collectors_security.go).
func (a *Agent) registerVMCollector(collectorLogger *slog.Logger) error {
	if a.config.Collectors.VM {
		a.logger.Warn("VM monitoring is only supported on Linux systems - collector disabled")
	}
	_ = collectorLogger
	return nil
}
