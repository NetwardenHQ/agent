package errors

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// RecoveryStrategy defines how to handle different types of errors
type RecoveryStrategy int

const (
	// StrategyRetry indicates the operation should be retried
	StrategyRetry RecoveryStrategy = iota
	// StrategyBackoff indicates the operation should be retried with backoff
	StrategyBackoff
	// StrategySkip indicates the operation should be skipped
	StrategySkip
	// StrategyFail indicates the operation should fail immediately
	StrategyFail
	// StrategyRestart indicates the component should restart
	StrategyRestart
)

// RecoveryHandler manages error recovery strategies
type RecoveryHandler struct {
	logger       *slog.Logger
	metrics      *ErrorMetrics
	strategies   map[ErrorType]RecoveryStrategy
	mu           sync.RWMutex
	panicHandler func(interface{})
	maxRetries   int
	baseBackoff  time.Duration
	maxBackoff   time.Duration
}

// RecoveryConfig configures the recovery handler
type RecoveryConfig struct {
	Logger       *slog.Logger
	Metrics      *ErrorMetrics
	MaxRetries   int
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration
	PanicHandler func(interface{})
}

// DefaultRecoveryConfig returns default recovery configuration
func DefaultRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		MaxRetries:  3,
		BaseBackoff: 1 * time.Second,
		MaxBackoff:  30 * time.Second,
	}
}

// NewRecoveryHandler creates a new recovery handler
func NewRecoveryHandler(config *RecoveryConfig) *RecoveryHandler {
	if config == nil {
		config = DefaultRecoveryConfig()
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	if config.Metrics == nil {
		config.Metrics = NewErrorMetrics()
	}

	rh := &RecoveryHandler{
		logger:       config.Logger,
		metrics:      config.Metrics,
		strategies:   make(map[ErrorType]RecoveryStrategy),
		maxRetries:   config.MaxRetries,
		baseBackoff:  config.BaseBackoff,
		maxBackoff:   config.MaxBackoff,
		panicHandler: config.PanicHandler,
	}

	// Set default strategies
	rh.SetStrategy(ErrTypeNetwork, StrategyBackoff)
	rh.SetStrategy(ErrTypeTimeout, StrategyRetry)
	rh.SetStrategy(ErrTypeRateLimit, StrategyBackoff)
	rh.SetStrategy(ErrTypeResource, StrategyBackoff)
	rh.SetStrategy(ErrTypeAuth, StrategyFail)
	rh.SetStrategy(ErrTypeConfig, StrategyFail)
	rh.SetStrategy(ErrTypeValidation, StrategySkip)
	rh.SetStrategy(ErrTypeInternal, StrategyRestart)

	return rh
}

// SetStrategy sets the recovery strategy for an error type
func (rh *RecoveryHandler) SetStrategy(errType ErrorType, strategy RecoveryStrategy) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	rh.strategies[errType] = strategy
}

// GetStrategy gets the recovery strategy for an error type
func (rh *RecoveryHandler) GetStrategy(errType ErrorType) RecoveryStrategy {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	if strategy, ok := rh.strategies[errType]; ok {
		return strategy
	}
	return StrategyFail
}

// HandleError handles an error according to its type and recovery strategy
func (rh *RecoveryHandler) HandleError(err error, operation string) RecoveryAction {
	if err == nil {
		return RecoveryAction{Strategy: StrategySkip}
	}

	// Record the error
	rh.metrics.RecordError(err)

	// Extract error type and metadata
	errType := GetErrorType(err)
	severity := GetSeverity(err)
	strategy := rh.GetStrategy(errType)

	// Log the error
	rh.logError(err, operation, severity)

	// Determine recovery action
	action := RecoveryAction{
		Strategy:   strategy,
		RetryDelay: rh.calculateRetryDelay(err),
		MaxRetries: rh.maxRetries,
	}

	// Override strategy for critical errors
	if severity == SeverityCritical {
		action.Strategy = StrategyFail
	}

	return action
}

// RecoverPanic recovers from a panic and converts it to an error
func (rh *RecoveryHandler) RecoverPanic(operation string) (err error) {
	if r := recover(); r != nil {
		// Get stack trace
		stack := debug.Stack()

		// Create panic error
		panicErr := NewError(ErrTypeInternal, fmt.Sprintf("panic recovered: %v", r)).
			WithCause(fmt.Errorf("panic: %v", r)).
			WithComponent("recovery").
			WithOperation(operation).
			WithContext("stack", string(stack)).
			WithSeverity(SeverityCritical).
			Build()

		// Log the panic
		rh.logger.Error("Panic recovered",
			"operation", operation,
			"panic", r,
			"stack", string(stack),
		)

		// Record panic metric
		rh.metrics.RecordPanic()

		// Call panic handler if configured
		if rh.panicHandler != nil {
			rh.panicHandler(r)
		}

		return panicErr
	}
	return nil
}

// ExecuteWithRecovery executes a function with panic recovery
func (rh *RecoveryHandler) ExecuteWithRecovery(operation string, fn func() error) (err error) {
	defer func() {
		if panicErr := rh.RecoverPanic(operation); panicErr != nil {
			err = panicErr
		}
	}()

	return fn()
}

// ExecuteWithRetry executes a function with retry logic based on error type
func (rh *RecoveryHandler) ExecuteWithRetry(operation string, fn func() error) error {
	var lastErr error
	attempt := 0

	for attempt < rh.maxRetries {
		// Execute with panic recovery
		err := rh.ExecuteWithRecovery(operation, fn)
		if err == nil {
			if attempt > 0 {
				rh.metrics.RecordRecovery(lastErr)
			}
			return nil
		}

		lastErr = err
		attempt++

		// Get recovery action
		action := rh.HandleError(err, operation)

		// Check if we should retry
		if action.Strategy == StrategyFail || action.Strategy == StrategySkip {
			return err
		}

		if attempt >= rh.maxRetries {
			rh.metrics.RecordMaxRetriesExceeded(err)
			return fmt.Errorf("max retries exceeded: %w", err)
		}

		// Calculate backoff
		var delay time.Duration
		if action.Strategy == StrategyBackoff {
			delay = rh.calculateBackoff(attempt, action.RetryDelay)
		} else {
			delay = action.RetryDelay
		}

		rh.logger.Info("Retrying operation",
			"operation", operation,
			"attempt", attempt,
			"delay", delay,
			"error", err.Error(),
		)

		rh.metrics.RecordRetry(err)
		time.Sleep(delay)
	}

	return fmt.Errorf("operation failed after %d attempts: %w", attempt, lastErr)
}

// calculateRetryDelay calculates the retry delay for an error
func (rh *RecoveryHandler) calculateRetryDelay(err error) time.Duration {
	if agentErr, ok := err.(*AgentError); ok {
		if agentErr.RetryAfter > 0 {
			return agentErr.RetryAfter
		}
	}
	return rh.baseBackoff
}

// calculateBackoff calculates exponential backoff with jitter
func (rh *RecoveryHandler) calculateBackoff(attempt int, baseDelay time.Duration) time.Duration {
	if baseDelay == 0 {
		baseDelay = rh.baseBackoff
	}

	// Exponential backoff: delay = base * 2^attempt
	delay := baseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > rh.maxBackoff {
			delay = rh.maxBackoff
			break
		}
	}

	// Add jitter (±25%)
	jitter := time.Duration(float64(delay) * 0.25 * (2*float64(time.Now().UnixNano()%100)/100 - 1))
	delay += jitter

	if delay < 0 {
		delay = baseDelay
	}

	return delay
}

// logError logs an error with appropriate level based on severity
func (rh *RecoveryHandler) logError(err error, operation string, severity Severity) {
	fields := []any{
		"operation", operation,
		"error", err.Error(),
		"error_type", GetErrorType(err),
	}

	if agentErr, ok := err.(*AgentError); ok {
		if agentErr.Component != "" {
			fields = append(fields, "component", agentErr.Component)
		}
		if len(agentErr.Context) > 0 {
			for k, v := range agentErr.Context {
				fields = append(fields, k, v)
			}
		}
	}

	switch severity {
	case SeverityCritical:
		rh.logger.Error("Critical error occurred", fields...)
	case SeverityHigh:
		rh.logger.Error("Error occurred", fields...)
	case SeverityMedium:
		rh.logger.Warn("Error occurred", fields...)
	case SeverityLow:
		rh.logger.Info("Minor error occurred", fields...)
	default:
		rh.logger.Debug("Error occurred", fields...)
	}
}

// RecoveryAction describes what action to take for error recovery
type RecoveryAction struct {
	Strategy   RecoveryStrategy
	RetryDelay time.Duration
	MaxRetries int
}

// CircuitBreaker provides circuit breaker functionality for error recovery
type CircuitBreaker struct {
	mu            sync.RWMutex
	failureCount  int
	lastFailTime  time.Time
	state         CircuitState
	threshold     int
	timeout       time.Duration
	halfOpenLimit int
	successCount  int
}

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	// StateClosed allows requests through
	StateClosed CircuitState = iota
	// StateOpen blocks requests
	StateOpen
	// StateHalfOpen allows limited requests for testing
	StateHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:         StateClosed,
		threshold:     threshold,
		timeout:       timeout,
		halfOpenLimit: 3,
	}
}

// Execute runs a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()

	// Check circuit state
	if cb.state == StateOpen {
		if time.Since(cb.lastFailTime) > cb.timeout {
			// Try to recover
			cb.state = StateHalfOpen
			cb.successCount = 0
		} else {
			cb.mu.Unlock()
			return fmt.Errorf("circuit breaker is open")
		}
	}

	if cb.state == StateHalfOpen && cb.successCount >= cb.halfOpenLimit {
		// Fully recover
		cb.state = StateClosed
		cb.failureCount = 0
	}

	cb.mu.Unlock()

	// Execute function
	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failureCount++
		cb.lastFailTime = time.Now()

		if cb.failureCount >= cb.threshold {
			cb.state = StateOpen
		}

		if cb.state == StateHalfOpen {
			// Failed in half-open, go back to open
			cb.state = StateOpen
		}
	} else {
		if cb.state == StateHalfOpen {
			cb.successCount++
		}
		if cb.state == StateClosed {
			cb.failureCount = 0
		}
	}

	return err
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = StateClosed
	cb.failureCount = 0
	cb.successCount = 0
}
