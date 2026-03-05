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

	"netwarden/internal/agent"
	"netwarden/internal/config"
	sharedhttp "netwarden/internal/http"
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
		elog.Info(1, "Service is now running and accepting control requests")
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

// runService runs the application as a Windows service.
func runService(configFile string, isDebug bool) error {
	var err error

	if isDebug {
		// Run in debug mode (console with service-like behavior)
		elog := debug.New(serviceName)
		defer elog.Close()

		fmt.Printf("Running Netwarden in Windows service debug mode\n")

		run := svc.Run
		run = debug.Run

		service := &netwardenService{
			configFile: configFile,
		}

		err = run(serviceName, service)
	} else {
		// Run as actual Windows service
		elog, err := eventlog.Open(serviceName)
		if err != nil {
			return fmt.Errorf("failed to open event log: %v", err)
		}
		defer elog.Close()

		elog.Info(1, "starting Netwarden Windows service")

		service := &netwardenService{
			configFile: configFile,
		}

		err = svc.Run(serviceName, service)
	}

	if err != nil {
		return fmt.Errorf("failed to run service: %v", err)
	}

	return nil
}

// checkServiceMode determines if we're running as a Windows service.
func checkServiceMode() (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("failed to check if running as Windows service: %v", err)
	}
	return isService, nil
}
