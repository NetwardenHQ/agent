//go:build !windows

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// runPlatformService reports whether the process is being run as a platform
// service and, if so, runs it. Only Windows has a service control manager to
// answer; everywhere else the agent runs in the foreground under systemd,
// launchd or the operator's supervisor of choice.
func runPlatformService(string, bool) (handled bool, err error) {
	return false, nil
}

// hup receives SIGHUP from the moment catchHangup runs.
var hup = make(chan os.Signal, 1)

// catchHangup subscribes to SIGHUP before anything else happens. SIGHUP's
// default action terminates the process, so a rotator signalling an agent
// that is still starting, or that logs to stderr, would otherwise kill it.
func catchHangup() {
	signal.Notify(hup, syscall.SIGHUP)
}

// watchLogReopen reopens the log file on SIGHUP, which is how newsyslog(8)
// and logrotate tell a daemon its log was rotated. With no log file (logging
// went to stderr) the signal is consumed and ignored.
func watchLogReopen(file *logFile, logger *slog.Logger) {
	go func() {
		for range hup {
			if file == nil {
				logger.Debug("ignoring SIGHUP: logging to stderr, nothing to reopen")
				continue
			}
			if err := file.Reopen(); err != nil {
				logger.Error("could not reopen log file after SIGHUP", "path", file.path, "error", err)
				continue
			}
			logger.Info("reopened log file", "path", file.path)
		}
	}()
}
