//go:build windows
// +build windows

// Package main provides Windows Service Control Manager integration for the Netwarden agent.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/NetwardenHQ/agent/internal/agent"
	"github.com/NetwardenHQ/agent/internal/config"
	sharedhttp "github.com/NetwardenHQ/agent/internal/http"
)

const serviceName = "Netwarden"

// netwardenService implements the Windows service interface.
type netwardenService struct {
	configFile  string
	config      *config.Config
	logger      *slog.Logger
	agent       *agent.Agent
	ctx         context.Context
	cancel      context.CancelFunc
	stopChannel chan struct{}
}

// Execute is called by the Windows Service Control Manager when the service is started.
// It handles service control requests (start, stop, pause, continue, etc.).
func (s *netwardenService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue

	// CRITICAL: Report to Windows SCM immediately to avoid timeout
	changes <- svc.Status{State: svc.StartPending}

	// Try to open event log for early debugging (but don't fail if it doesn't work)
	elog, elogErr := eventlog.Open(serviceName)
	if elogErr == nil {
		elog.Info(1, "Netwarden service Execute() called, loading configuration...")
		defer elog.Close()
	}

	// Load configuration after reporting StartPending
	cfg, err := config.LoadConfig(s.configFile)
	if err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("failed to load config from %s: %v", s.configFile, err))
		}
		return true, 1
	}
	s.config = cfg

	// Configure HTTP client with TLS settings
	if cfg.TLSSkipVerify || cfg.TLSCACert != "" {
		tlsCfg := &sharedhttp.TLSConfig{
			SkipVerify: cfg.TLSSkipVerify,
			CACertPath: cfg.TLSCACert,
		}
		if err := sharedhttp.InitClient(tlsCfg); err != nil {
			if elog != nil {
				elog.Error(1, fmt.Sprintf("TLS configuration error: %v", err))
			}
			return true, 1
		}
	}

	if elog != nil {
		elog.Info(1, "Configuration loaded successfully, setting up logging...")
	}

	// Setup logging after config is loaded
	logger := setupLoggingWithFile(cfg.LogLevel, "json", cfg.LogFile)
	s.logger = logger
	logConfigWarnings(cfg, logger)

	s.logger.Info("Netwarden Windows service starting",
		"config_file", s.configFile,
		"tenant_id", cfg.TenantID[:6]+"****", // Log partial tenant ID for debugging
	)

	if elog != nil {
		elog.Info(1, "Logging configured, creating agent...")
	}

	// Initialize agent with version
	s.agent, err = agent.New(s.config, s.logger, version)
	if err != nil {
		s.logger.Error("failed to create agent in service mode", "error", err)
		if elog != nil {
			elog.Error(1, fmt.Sprintf("failed to create agent: %v", err))
		}
		return true, 1
	}

	s.logger.Info("Netwarden Windows service initialized successfully")
	if elog != nil {
		elog.Info(1, "Agent created successfully, starting service...")
	}

	// Create context for graceful shutdown
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.stopChannel = make(chan struct{})

	// Start the agent in a goroutine
	agentErrors := make(chan error, 1)
	go func() {
		agentErrors <- s.agent.Run(s.ctx)
		close(s.stopChannel)
	}()

	// Set service status to running
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.logger.Info("Netwarden Windows service started and running")
	if elog != nil {
		elog.Info(1, "service running and accepting control requests")
	}

	// Main service loop - handle control requests
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				s.logger.Info("received stop/shutdown request, stopping service")
				if elog != nil {
					elog.Info(1, "Received stop/shutdown request")
				}
				changes <- svc.Status{State: svc.StopPending}

				// Cancel the agent context
				s.cancel()

				// Wait for agent to stop gracefully with timeout
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer shutdownCancel()

				if err := s.agent.Shutdown(shutdownCtx); err != nil {
					s.logger.Error("error during graceful shutdown", "error", err)
					if elog != nil {
						elog.Error(1, fmt.Sprintf("error during shutdown: %v", err))
					}
				} else {
					s.logger.Info("agent shutdown completed successfully")
					if elog != nil {
						elog.Info(1, "Agent shutdown completed successfully")
					}
				}

				// Service stopped successfully
				return false, 0

			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				s.logger.Info("service paused")

			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				s.logger.Info("service resumed")

			default:
				s.logger.Warn("received unexpected service control request", "cmd", c.Cmd)
			}

		case err := <-agentErrors:
			// Agent stopped/failed
			if err != nil {
				s.logger.Error("agent failed", "error", err)
				if elog != nil {
					elog.Error(1, fmt.Sprintf("agent failed: %v", err))
				}
				return true, 1
			}
			s.logger.Info("agent exited normally")
			if elog != nil {
				elog.Info(1, "Agent exited normally")
			}
			return false, 0

		case <-s.stopChannel:
			// Agent stopped gracefully
			s.logger.Info("agent stopped, stopping service")
			if elog != nil {
				elog.Info(1, "Agent stopped gracefully")
			}
			return false, 0
		}
	}
}

// runPlatformService runs the agent as a Windows service when the service
// control manager started it, or when --service-debug asks for the service
// code path in a console. It reports handled=false when the agent should run
// in the foreground.
func runPlatformService(configFile string, serviceDebug bool) (handled bool, err error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return true, fmt.Errorf("failed to check if running as Windows service: %w", err)
	}
	if !isService && !serviceDebug {
		return false, nil
	}

	service := &netwardenService{configFile: configFile}

	if serviceDebug {
		elog := debug.New(serviceName)
		defer elog.Close()
		fmt.Println("Running Netwarden in Windows service debug mode")
		if err := debug.Run(serviceName, service); err != nil {
			return true, fmt.Errorf("failed to run service: %w", err)
		}
		return true, nil
	}

	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return true, fmt.Errorf("failed to open event log: %w", err)
	}
	defer elog.Close()
	elog.Info(1, "starting Netwarden Windows service")

	if err := svc.Run(serviceName, service); err != nil {
		return true, fmt.Errorf("failed to run service: %w", err)
	}
	return true, nil
}

// catchHangup is a no-op on Windows, which has no SIGHUP.
func catchHangup() {}

// watchLogReopen is a no-op on Windows: there is no SIGHUP, and the Windows
// agent's log is not rotated by renaming it underneath the process.
func watchLogReopen(*logFile, *slog.Logger) {}
