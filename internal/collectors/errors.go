package collectors

import (
	"fmt"
)

// ErrorType represents the category of collector error.
type ErrorType string

const (
	// ErrorTypeCollection indicates an error during metric collection.
	ErrorTypeCollection ErrorType = "collection"

	// ErrorTypeConfiguration indicates a configuration error.
	ErrorTypeConfiguration ErrorType = "configuration"

	// ErrorTypeConnection indicates a connection error.
	ErrorTypeConnection ErrorType = "connection"

	// ErrorTypePermission indicates a permission error.
	ErrorTypePermission ErrorType = "permission"

	// ErrorTypeTimeout indicates a timeout error.
	ErrorTypeTimeout ErrorType = "timeout"

	// ErrorTypeNotSupported indicates the collector is not supported on this platform.
	ErrorTypeNotSupported ErrorType = "not_supported"
)

// CollectorError represents an error from a collector with context.
type CollectorError struct {
	Collector string
	Type      ErrorType
	Message   string
	Err       error
}

// Error implements the error interface.
func (e *CollectorError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s collector %s error: %s: %v", e.Collector, e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s collector %s error: %s", e.Collector, e.Type, e.Message)
}

// Unwrap returns the wrapped error.
func (e *CollectorError) Unwrap() error {
	return e.Err
}

// IsRetryable returns true if the error is potentially retryable.
func (e *CollectorError) IsRetryable() bool {
	switch e.Type {
	case ErrorTypeTimeout, ErrorTypeConnection:
		return true
	default:
		return false
	}
}

// NewCollectorError creates a new collector error.
func NewCollectorError(collector string, errType ErrorType, message string, err error) *CollectorError {
	return &CollectorError{
		Collector: collector,
		Type:      errType,
		Message:   message,
		Err:       err,
	}
}

// WrapError wraps an error with collector context.
func WrapError(collector string, errType ErrorType, err error) *CollectorError {
	if err == nil {
		return nil
	}
	return &CollectorError{
		Collector: collector,
		Type:      errType,
		Message:   err.Error(),
		Err:       err,
	}
}
