// Copyright 2024-2026 Netwarden
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main is the Netwarden agent entry point.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/NetwardenHQ/agent/internal/agent"
	"github.com/NetwardenHQ/agent/internal/config"
	sharedhttp "github.com/NetwardenHQ/agent/internal/http"
)

var (
	// Version info is set at build time via ldflags
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

// getDefaultConfigPath returns the default configuration path based on the operating system.
func getDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		// On Windows, look for config file in the same directory as the executable
		executable, err := os.Executable()
		if err != nil {
			// Fallback to current directory if we can't get executable path
			return "netwarden.conf"
		}

		execDir := filepath.Dir(executable)
		return filepath.Join(execDir, "netwarden.conf")
	}

	// FreeBSD keeps third-party configuration under /usr/local/etc (hier(7)),
	// which is where the FreeBSD package installs it.
	if runtime.GOOS == "freebsd" {
		return "/usr/local/etc/netwarden/netwarden.conf"
	}

	// On other Unix systems, use the traditional /etc location
	return "/etc/netwarden/netwarden.conf"
}

func main() {
	// Before anything can block: an unhandled SIGHUP would kill the agent.
	catchHangup()

	// Get default config path based on OS
	defaultConfigPath := getDefaultConfigPath()

	var (
		configFile   string
		showVersion  = flag.Bool("version", false, "Show version information and exit")
		createConfig = flag.Bool("create-config", false, "Create example configuration file and exit")
		serviceDebug = flag.Bool("service-debug", false, "Run in Windows service debug mode (Windows only)")
	)
	flag.StringVar(&configFile, "config", defaultConfigPath, "Path to configuration file")
	flag.StringVar(&configFile, "c", defaultConfigPath, "Path to configuration file (shortcut)")

	// Custom usage function to display flags with -- prefix (GNU-style)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Netwarden Agent - infrastructure and security monitoring\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --config PATH, -c PATH\n")
		fmt.Fprintf(os.Stderr, "        Path to configuration file (default: %s)\n", defaultConfigPath)
		fmt.Fprintf(os.Stderr, "  --version\n")
		fmt.Fprintf(os.Stderr, "        Show version information and exit\n")
		fmt.Fprintf(os.Stderr, "  --create-config\n")
		fmt.Fprintf(os.Stderr, "        Create example configuration file and exit\n")
		fmt.Fprintf(os.Stderr, "  --service-debug\n")
		fmt.Fprintf(os.Stderr, "        Run in Windows service debug mode (Windows only)\n")
		fmt.Fprintf(os.Stderr, "  --help, -h\n")
		fmt.Fprintf(os.Stderr, "        Show this help message\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("Netwarden Agent\n")
		fmt.Printf("Version:    %s\n", version)
		fmt.Printf("Build Date: %s\n", buildDate)
		fmt.Printf("Git Commit: %s\n", gitCommit)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *createConfig {
		if err := config.CreateConfigFile(configFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create configuration file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created configuration file: %s\n", configFile)
		fmt.Println("Please edit the file with your credentials and restart the agent:")
		fmt.Println("  1. Set your tenant_id (10-character string)")
		fmt.Println("  2. Set your api_key (nw_sk_...)")
		fmt.Println("  3. Start the agent: netwarden")
		os.Exit(0)
	}

	// A Windows service must answer the service control manager before it
	// loads anything, so that check comes before the config is read. On every
	// other platform this is a no-op.
	if handled, err := runPlatformService(configFile, *serviceDebug); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Windows service failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "Error: Configuration file not found at %s\n", configFile)
			fmt.Println("To create a configuration file, run:")
			fmt.Println("  netwarden --create-config")
			fmt.Println("Then edit the file to provide your tenant_id and api_key.")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Configure HTTP client with TLS settings (before any network calls)
	if cfg.TLSSkipVerify || cfg.TLSCACert != "" {
		tlsCfg := &sharedhttp.TLSConfig{
			SkipVerify: cfg.TLSSkipVerify,
			CACertPath: cfg.TLSCACert,
		}
		if err := sharedhttp.InitClient(tlsCfg); err != nil {
			fmt.Fprintf(os.Stderr, "TLS configuration error: %v\n", err)
			os.Exit(1)
		}
	}

	// The agent runs as a daemon, so it always logs to a file.
	logger := setupLoggingWithFile(cfg.LogLevel, "json", cfg.LogFile)
	logConfigWarnings(cfg, logger)

	// Log startup information
	logFields := []any{
		"version", version,
		"config_file", configFile,
	}
	if cfg.ServerURL != config.DefaultServerURL {
		logFields = append(logFields, "server_url", cfg.ServerURL)
	}
	if cfg.TLSSkipVerify {
		logFields = append(logFields, "tls_skip_verify", true)
		logger.Warn("TLS certificate verification is disabled; connections are not secure")
	}
	if cfg.TLSCACert != "" {
		logFields = append(logFields, "tls_ca_cert", cfg.TLSCACert)
	}
	logger.Info("starting Netwarden agent", logFields...)

	runConsoleMode(cfg, logger)
}

// runConsoleMode runs the agent in the foreground until SIGINT/SIGTERM.
func runConsoleMode(cfg *config.Config, logger *slog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	netwardenAgent, err := agent.New(cfg, logger, version)
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	agentErrors := make(chan error, 1)
	go func() {
		agentErrors <- netwardenAgent.Run(ctx)
	}()

	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig)
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := netwardenAgent.Shutdown(shutdownCtx); err != nil {
			logger.Error("error during graceful shutdown", "error", err)
			os.Exit(1)
		}

	case err := <-agentErrors:
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("agent failed", "error", err)
			os.Exit(1)
		}
		logger.Info("agent exited")
	}
}

// setupLogging configures structured logging based on configuration.
func setupLogging(level, format string, output io.Writer) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
			}
			return a
		},
	}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewJSONHandler(output, opts)
	}

	return slog.New(handler)
}

// setupLoggingWithFile configures logging to write to a log file with fallback.
func setupLoggingWithFile(level, format, configLogFile string) *slog.Logger {
	var logFile string
	if configLogFile != "" {
		logFile = configLogFile
	} else {
		logFile = getLogFilePath()
	}

	file, err := openLogFile(logFile)
	if err != nil {
		// If we can't open the preferred log file, fall back to stderr
		fmt.Fprintf(os.Stderr, "Warning: Could not open log file %s: %v. Logging to stderr.\n", logFile, err)
		logger := setupLogging(level, format, os.Stderr)
		watchLogReopen(nil, logger)
		return logger
	}

	logger := setupLogging(level, format, file)
	watchLogReopen(file, logger)
	return logger
}

// logConfigWarnings logs what LoadConfig found but could not log itself,
// because the log file was not open yet.
func logConfigWarnings(cfg *config.Config, logger *slog.Logger) {
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}
}

// getLogFilePath returns the appropriate log file path based on OS.
//
// There is deliberately no fallback to a world-writable directory such as
// /tmp: if /var/log/netwarden is unusable the open fails and the agent logs
// to stderr, which its supervisor captures.
func getLogFilePath() string {
	if runtime.GOOS == "windows" {
		// On Windows, use the same directory as the executable
		executable, err := os.Executable()
		if err != nil {
			// Fallback to current directory if we can't get executable path
			return "netwarden.log"
		}

		execDir := filepath.Dir(executable)
		return filepath.Join(execDir, "netwarden.log")
	}

	// On Unix systems, log to /var/log/netwarden/netwarden.log. A failure to
	// create the directory surfaces when the file is opened.
	logDir := "/var/log/netwarden"
	_ = os.MkdirAll(logDir, 0o755)
	return filepath.Join(logDir, "netwarden.log")
}
