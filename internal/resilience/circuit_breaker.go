// Package resilience provides circuit breaker pattern for fault tolerance.
package resilience

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CircuitState represents the current state of a circuit breaker.
type CircuitState int

const (
	// StateClosed - circuit is closed, requests pass through normally
	StateClosed CircuitState = iota
	// StateOpen - circuit is open, requests fail immediately
	StateOpen
	// StateHalfOpen - circuit allows limited requests to test if service recovered
	StateHalfOpen
)

// String returns the string representation of a circuit state.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures the circuit breaker behavior.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures that triggers the circuit to open.
	// Default: 5
	FailureThreshold int

	// RecoveryTimeout is how long the circuit stays open before transitioning to half-open.
	// Default: 30 seconds
	RecoveryTimeout time.Duration

	// SuccessThreshold is the number of consecutive successes in half-open state to close the circuit.
	// Default: 3
	SuccessThreshold int

	// Timeout is the maximum time to wait for an operation to complete.
	// Default: 10 seconds
	Timeout time.Duration

	// Name is a human-readable name for this circuit breaker.
	Name string

	// Logger for circuit breaker events.
	Logger *slog.Logger
}

// DefaultCircuitBreakerConfig returns a circuit breaker configuration with sensible defaults.
func DefaultCircuitBreakerConfig(name string) CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		RecoveryTimeout:  30 * time.Second,
		SuccessThreshold: 3,
		Timeout:          10 * time.Second,
		Name:             name,
		Logger:           slog.Default(),
	}
}

// CircuitBreaker implements the circuit breaker pattern to prevent cascade failures.
type CircuitBreaker struct {
	config CircuitBreakerConfig
	logger *slog.Logger

	// State management
	state           CircuitState
	failures        int
	successes       int
	lastFailureTime time.Time
	mu              sync.RWMutex

	// Statistics
	totalAttempts   int64
	totalFailures   int64
	totalSuccesses  int64
	totalRejections int64
	stateMu         sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	// Set defaults
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.RecoveryTimeout <= 0 {
		config.RecoveryTimeout = 30 * time.Second
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 3
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.Name == "" {
		config.Name = "circuit-breaker"
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &CircuitBreaker{
		config: config,
		logger: config.Logger.With("component", "circuit_breaker", "name", config.Name),
		state:  StateClosed,
	}
}

// Execute runs the given function with circuit breaker protection.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	// Check if circuit should allow the request
	if !cb.allowRequest() {
		cb.recordRejection()
		return fmt.Errorf("circuit breaker %s is open", cb.config.Name)
	}

	cb.recordAttempt()

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, cb.config.Timeout)
	defer cancel()

	// Execute the function
	err := fn(timeoutCtx)

	// Record the result
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// allowRequest determines if a request should be allowed through the circuit breaker.
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if enough time has passed to transition to half-open
		if time.Since(cb.lastFailureTime) > cb.config.RecoveryTimeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			// Double-check after acquiring write lock
			if cb.state == StateOpen && time.Since(cb.lastFailureTime) > cb.config.RecoveryTimeout {
				cb.state = StateHalfOpen
				cb.successes = 0
				cb.logger.Info("Circuit breaker transitioning to half-open",
					"recovery_timeout", cb.config.RecoveryTimeout)
			}
			cb.mu.Unlock()
			cb.mu.RLock()
			return cb.state == StateHalfOpen
		}
		return false
	case StateHalfOpen:
		// Allow requests in half-open state to test recovery
		return true
	default:
		return false
	}
}

// recordAttempt increments the total attempts counter.
func (cb *CircuitBreaker) recordAttempt() {
	cb.stateMu.Lock()
	cb.totalAttempts++
	cb.stateMu.Unlock()
}

// recordFailure records a failed operation.
func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.stateMu.Lock()
	cb.totalFailures++
	cb.stateMu.Unlock()

	cb.failures++
	cb.successes = 0 // Reset success count on failure
	cb.lastFailureTime = time.Now()

	// Check if circuit should open
	if cb.state == StateClosed && cb.failures >= cb.config.FailureThreshold {
		cb.state = StateOpen
		cb.logger.Warn("Circuit breaker opened due to consecutive failures",
			"failures", cb.failures,
			"threshold", cb.config.FailureThreshold)
	} else if cb.state == StateHalfOpen {
		// Failed in half-open state, go back to open
		cb.state = StateOpen
		cb.logger.Warn("Circuit breaker returned to open state after half-open failure")
	}
}

// recordSuccess records a successful operation.
func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.stateMu.Lock()
	cb.totalSuccesses++
	cb.stateMu.Unlock()

	cb.failures = 0 // Reset failure count on success

	if cb.state == StateHalfOpen {
		cb.successes++
		// Check if circuit should close
		if cb.successes >= cb.config.SuccessThreshold {
			cb.state = StateClosed
			cb.successes = 0
			cb.logger.Info("Circuit breaker closed after successful recovery",
				"success_threshold", cb.config.SuccessThreshold)
		}
	}
}

// recordRejection increments the rejection counter.
func (cb *CircuitBreaker) recordRejection() {
	cb.stateMu.Lock()
	cb.totalRejections++
	cb.stateMu.Unlock()
}

// GetState returns the current state of the circuit breaker.
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// CircuitBreakerStats provides statistics about circuit breaker performance.
type CircuitBreakerStats struct {
	Name             string     `json:"name"`
	State            string     `json:"state"`
	TotalAttempts    int64      `json:"total_attempts"`
	TotalSuccesses   int64      `json:"total_successes"`
	TotalFailures    int64      `json:"total_failures"`
	TotalRejections  int64      `json:"total_rejections"`
	SuccessRate      float64    `json:"success_rate"`
	FailureRate      float64    `json:"failure_rate"`
	CurrentFailures  int        `json:"current_failures"`
	CurrentSuccesses int        `json:"current_successes"`
	LastFailureTime  *time.Time `json:"last_failure_time,omitempty"`
}

// GetStats returns current circuit breaker statistics.
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	cb.stateMu.RLock()
	defer cb.mu.RUnlock()
	defer cb.stateMu.RUnlock()

	stats := CircuitBreakerStats{
		Name:             cb.config.Name,
		State:            cb.state.String(),
		TotalAttempts:    cb.totalAttempts,
		TotalSuccesses:   cb.totalSuccesses,
		TotalFailures:    cb.totalFailures,
		TotalRejections:  cb.totalRejections,
		CurrentFailures:  cb.failures,
		CurrentSuccesses: cb.successes,
	}

	if cb.totalAttempts > 0 {
		stats.SuccessRate = float64(cb.totalSuccesses) / float64(cb.totalAttempts) * 100
		stats.FailureRate = float64(cb.totalFailures) / float64(cb.totalAttempts) * 100
	}

	if !cb.lastFailureTime.IsZero() {
		stats.LastFailureTime = &cb.lastFailureTime
	}

	return stats
}

// Reset resets the circuit breaker to its initial state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	cb.stateMu.Lock()
	defer cb.mu.Unlock()
	defer cb.stateMu.Unlock()

	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.lastFailureTime = time.Time{}
	cb.totalAttempts = 0
	cb.totalSuccesses = 0
	cb.totalFailures = 0
	cb.totalRejections = 0

	cb.logger.Info("Circuit breaker reset to closed state")
}

// IsHealthy returns true if the circuit breaker is in a healthy state.
func (cb *CircuitBreaker) IsHealthy() bool {
	return cb.GetState() != StateOpen
}
