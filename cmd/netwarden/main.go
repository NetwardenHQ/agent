// Copyright 2024-2025 Netwarden
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

// Package main provides the Netwarden agent entry point with graceful shutdown,
// proper logging, and production-ready error handling.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"netwarden/internal/agent"
	"netwarden/internal/config"
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

	// On Unix systems, use the traditional /etc location
	return "/etc/netwarden/netwarden.conf"
}

func main() {
	// Get default config path based on OS
	defaultConfigPath := getDefaultConfigPath()

	// Parse command line flags
	var (
		configFile   = flag.String("config", defaultConfigPath, "Path to configuration file")
		configShort  = flag.String("c", defaultConfigPath, "Path to configuration file (shortcut)")
		showVersion  = flag.Bool("version", false, "Show version information and exit")
		createConfig = flag.Bool("create-config", false, "Create example configuration file and exit")
		serviceDebug = flag.Bool("service-debug", false, "Run in Windows service debug mode (Windows only)")
	)

	// Custom usage function to display flags with -- prefix (GNU-style)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Netwarden Agent - Enterprise-grade infrastructure monitoring\n\n")
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

	// Use short flag if provided
	if flag.Lookup("c").Value.String() != defaultConfigPath {
		*configFile = *configShort
	}

	// Handle version flag
	if *showVersion {
		fmt.Printf("Netwarden Agent\n")
		fmt.Printf("Version:    %s\n", version)
		fmt.Printf("Build Date: %s\n", buildDate)
		fmt.Printf("Git Commit: %s\n", gitCommit)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Handle config creation flag
	if *createConfig {
		// Create config in default location
		configPath := defaultConfigPath
		if err := config.CreateConfigFile(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create configuration file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created configuration file: %s\n", configPath)
		fmt.Println("Please edit the file with your credentials and restart the agent:")
		fmt.Printf("  1. Set your tenant_id (10-character string)\n")
		fmt.Printf("  2. Set your api_key (nw_sk_...)\n")
		fmt.Printf("  3. Start the agent: netwarden\n")
		os.Exit(0)
	}

	// On Windows, check if we should run as a service BEFORE loading config
	// This is critical to avoid the 30-second timeout for Windows services
	if runtime.GOOS == "windows" {
		// Check if running as Windows service or in debug mode
		isService, err := checkServiceMode()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to check service mode: %v\n", err)
			os.Exit(1)
		}

		if isService || *serviceDebug {
			// Run as Windows service - pass config file path for loading inside service
			if err := runService(*configFile, *serviceDebug); err != nil {
				fmt.Fprintf(os.Stderr, "Windows service failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// Load configuration (only for console mode)
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		// Check if config file doesn't exist by looking at the error
		if strings.Contains(err.Error(), "no such file or directory") {
			fmt.Fprintf(os.Stderr, "Error: Configuration file not found at %s\n", *configFile)
			fmt.Println("To create a configuration file, run:")
			fmt.Println("  netwarden --create-config")
			fmt.Println("Then edit the file to provide your tenant_id and api_key.")
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Setup structured logging - always log to file since we're always a daemon
	logger := setupLoggingWithFile(cfg.LogLevel, "json", cfg.LogFile)

	// Log startup information
	logger.Info("starting Netwarden agent",
		"version", version,
		"config_file", *configFile,
	)

	// Run in console mode (default for non-Windows or when not running as service)
	runConsoleMode(cfg, logger)
}

// runConsoleMode runs the agent in console mode with signal handling.
func runConsoleMode(cfg *config.Config, logger *slog.Logger) {
	logger.Info("running Netwarden in console mode")

	// Create main context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create and start the agent
	netwardenAgent, err := agent.New(cfg, logger, version)
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	// Start agent in goroutine
	agentErrors := make(chan error, 1)
	go func() {
		agentErrors <- netwardenAgent.Run(ctx)
	}()

	// Wait for shutdown signal or agent error
	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig)
		cancel() // Cancel context to signal shutdown

		// Give the agent time to shutdown gracefully
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := netwardenAgent.Shutdown(shutdownCtx); err != nil {
			logger.Error("error during graceful shutdown", "error", err)
			os.Exit(1)
		}

		logger.Info("agent shutdown completed")

	case err := <-agentErrors:
		if err != nil {
			logger.Error("agent failed", "error", err)
			os.Exit(1)
		}
		logger.Info("agent exited normally")
	}
}

// setupLogging configures structured logging based on configuration.
func setupLogging(level, format string, output *os.File) *slog.Logger {
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
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Add timestamp formatting if needed
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

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// If we can't open the preferred log file, fall back to stderr
		fmt.Fprintf(os.Stderr, "Warning: Could not open log file %s: %v. Logging to stderr.\n", logFile, err)
		return setupLogging(level, format, os.Stderr)
	}

	return setupLogging(level, format, file)
}

// getLogFilePath returns the appropriate log file path based on OS.
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

	// On Unix systems, prefer /var/log/netwarden/netwarden.log if we have permissions
	logDir := "/var/log/netwarden"
	preferredPath := filepath.Join(logDir, "netwarden.log")

	// Try to create the log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err == nil {
		// Test if we can write to the directory
		testFile := filepath.Join(logDir, ".netwarden_test")
		if file, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			defer func() {
				file.Close()
				os.Remove(testFile) // Clean up test file
			}()
			return preferredPath
		}
	}

	// Fall back to /tmp/netwarden.log
	return "/tmp/netwarden.log"
}

// runDaemon forks the process to run in the background.
func runDaemon() error {
	// Get the current executable path
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Prepare arguments (exclude the -d flag, add daemon marker)
	args := []string{}
	for i, arg := range os.Args[1:] {
		if arg == "-d" {
			continue
		}
		// Skip if previous arg was -d
		if i > 0 && os.Args[i] == "-d" {
			continue
		}
		args = append(args, arg)
	}

	// Add a special internal flag to mark this as a daemon child
	args = append(args, "--daemon-child")

	// Create process attributes for background execution
	procAttr := &os.ProcAttr{
		Env:   os.Environ(),
		Files: []*os.File{nil, nil, nil}, // Close stdin, stdout, stderr
	}

	// Start the background process
	proc, err := os.StartProcess(executable, append([]string{executable}, args...), procAttr)
	if err != nil {
		return fmt.Errorf("failed to start background process: %v", err)
	}

	fmt.Printf("Netwarden agent started in daemon mode (PID: %d)\n", proc.Pid)
	fmt.Printf("Logs will be written to: %s\n", getLogFilePath())

	// Release the process so it can run independently
	proc.Release()

	return nil
}
