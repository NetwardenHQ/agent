// Package errors provides structured error types and handling for the Netwarden agent
// with categorization for retryable vs fatal errors and context propagation.
package errors

import (
	"errors"
	"fmt"
	"time"
)

// ErrorType represents the category of error
type ErrorType int

const (
	// ErrTypeUnknown represents an unknown error type
	ErrTypeUnknown ErrorType = iota
	// ErrTypeNetwork represents network-related errors (retryable)
	ErrTypeNetwork
	// ErrTypeTimeout represents timeout errors (retryable)
	ErrTypeTimeout
	// ErrTypeRateLimit represents rate limiting errors (retryable with backoff)
	ErrTypeRateLimit
	// ErrTypeAuth represents authentication errors (fatal)
	ErrTypeAuth
	// ErrTypeConfig represents configuration errors (fatal)
	ErrTypeConfig
	// ErrTypeValidation represents validation errors (fatal)
	ErrTypeValidation
	// ErrTypeResource represents resource errors (may be retryable)
	ErrTypeResource
	// ErrTypeInternal represents internal errors (fatal)
	ErrTypeInternal
)

// Severity represents the severity level of an error
type Severity int

const (
	// SeverityLow indicates a minor issue that doesn't affect functionality
	SeverityLow Severity = iota
	// SeverityMedium indicates an issue that may degrade functionality
	SeverityMedium
	// SeverityHigh indicates a serious issue affecting core functionality
	SeverityHigh
	// SeverityCritical indicates a critical failure requiring immediate attention
	SeverityCritical
)

// AgentError represents a structured error with context and metadata
type AgentError struct {
	Type       ErrorType
	Severity   Severity
	Message    string
	Cause      error
	Component  string
	Operation  string
	Timestamp  time.Time
	Retryable  bool
	RetryAfter time.Duration
	Context    map[string]interface{}
}

// Error implements the error interface
func (e *AgentError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Component, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Component, e.Message)
}

func (e *AgentError) Unwrap() error {
	return e.Cause
}

// Is implements error matching
func (e *AgentError) Is(target error) bool {
	t, ok := target.(*AgentError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

func (e *AgentError) IsRetryable() bool {
	return e.Retryable
}

func (e *AgentError) GetRetryDelay() time.Duration {
	if e.RetryAfter > 0 {
		return e.RetryAfter
	}
	// Default retry delays based on error type
	switch e.Type {
	case ErrTypeRateLimit:
		return 60 * time.Second
	case ErrTypeNetwork, ErrTypeTimeout:
		return 5 * time.Second
	case ErrTypeResource:
		return 10 * time.Second
	default:
		return 0
	}
}

// ErrorBuilder provides a fluent interface for building errors
type ErrorBuilder struct {
	err *AgentError
}

// NewError creates a new error builder
func NewError(errType ErrorType, message string) *ErrorBuilder {
	return &ErrorBuilder{
		err: &AgentError{
			Type:      errType,
			Message:   message,
			Timestamp: time.Now(),
			Severity:  SeverityMedium,
			Context:   make(map[string]interface{}),
			Retryable: isRetryableType(errType),
		},
	}
}

// WithCause adds the underlying cause
func (b *ErrorBuilder) WithCause(cause error) *ErrorBuilder {
	b.err.Cause = cause
	return b
}

// WithComponent sets the component where the error occurred
func (b *ErrorBuilder) WithComponent(component string) *ErrorBuilder {
	b.err.Component = component
	return b
}

// WithOperation sets the operation that failed
func (b *ErrorBuilder) WithOperation(operation string) *ErrorBuilder {
	b.err.Operation = operation
	return b
}

// WithSeverity sets the error severity
func (b *ErrorBuilder) WithSeverity(severity Severity) *ErrorBuilder {
	b.err.Severity = severity
	return b
}

// WithRetryable explicitly sets whether the error is retryable
func (b *ErrorBuilder) WithRetryable(retryable bool) *ErrorBuilder {
	b.err.Retryable = retryable
	return b
}

// WithRetryAfter sets the retry delay
func (b *ErrorBuilder) WithRetryAfter(delay time.Duration) *ErrorBuilder {
	b.err.RetryAfter = delay
	b.err.Retryable = true
	return b
}

func (b *ErrorBuilder) WithContext(key string, value interface{}) *ErrorBuilder {
	b.err.Context[key] = value
	return b
}

func (b *ErrorBuilder) Build() *AgentError {
	return b.err
}

// isRetryableType determines if an error type is retryable by default
func isRetryableType(errType ErrorType) bool {
	switch errType {
	case ErrTypeNetwork, ErrTypeTimeout, ErrTypeRateLimit, ErrTypeResource:
		return true
	default:
		return false
	}
}

// Common error constructors

// NetworkError creates a network error
func NetworkError(message string, cause error) *AgentError {
	return NewError(ErrTypeNetwork, message).
		WithCause(cause).
		WithComponent("network").
		Build()
}

// TimeoutError creates a timeout error
func TimeoutError(operation string, timeout time.Duration) *AgentError {
	return NewError(ErrTypeTimeout, fmt.Sprintf("operation timed out after %v", timeout)).
		WithOperation(operation).
		WithComponent("network").
		WithContext("timeout", timeout).
		Build()
}

// AuthError creates an authentication error
func AuthError(message string) *AgentError {
	return NewError(ErrTypeAuth, message).
		WithComponent("auth").
		WithSeverity(SeverityCritical).
		Build()
}

// ConfigError creates a configuration error
func ConfigError(message string, field string) *AgentError {
	return NewError(ErrTypeConfig, message).
		WithComponent("config").
		WithContext("field", field).
		WithSeverity(SeverityCritical).
		Build()
}

// ValidationError creates a validation error
func ValidationError(message string, value interface{}) *AgentError {
	return NewError(ErrTypeValidation, message).
		WithComponent("validation").
		WithContext("value", value).
		Build()
}

// RateLimitError creates a rate limit error
func RateLimitError(retryAfter time.Duration) *AgentError {
	return NewError(ErrTypeRateLimit, "rate limit exceeded").
		WithComponent("api").
		WithRetryAfter(retryAfter).
		WithSeverity(SeverityLow).
		Build()
}

// ResourceError creates a resource error
func ResourceError(resource string, message string) *AgentError {
	return NewError(ErrTypeResource, message).
		WithComponent("resource").
		WithContext("resource", resource).
		Build()
}

// InternalError creates an internal error
func InternalError(message string, cause error) *AgentError {
	return NewError(ErrTypeInternal, message).
		WithCause(cause).
		WithComponent("internal").
		WithSeverity(SeverityHigh).
		Build()
}

// Error helpers

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	var agentErr *AgentError
	if errors.As(err, &agentErr) {
		return agentErr.IsRetryable()
	}
	return false
}

func GetRetryDelay(err error) time.Duration {
	var agentErr *AgentError
	if errors.As(err, &agentErr) {
		return agentErr.GetRetryDelay()
	}
	return 0
}

func GetErrorType(err error) ErrorType {
	var agentErr *AgentError
	if errors.As(err, &agentErr) {
		return agentErr.Type
	}
	return ErrTypeUnknown
}

func GetSeverity(err error) Severity {
	var agentErr *AgentError
	if errors.As(err, &agentErr) {
		return agentErr.Severity
	}
	return SeverityMedium
}

// WrapError wraps an existing error with agent error metadata
func WrapError(err error, errType ErrorType, component string) *AgentError {
	if err == nil {
		return nil
	}

	// If already an AgentError, preserve the original and add context
	var agentErr *AgentError
	if errors.As(err, &agentErr) {
		// Create a new error that wraps the existing one
		return NewError(errType, agentErr.Message).
			WithCause(err).
			WithComponent(component).
			WithSeverity(agentErr.Severity).
			Build()
	}

	return NewError(errType, err.Error()).
		WithCause(err).
		WithComponent(component).
		Build()
}
