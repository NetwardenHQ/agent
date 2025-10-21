// Package resilience provides simple retry logic for network operations.
package resilience

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Retry performs a simple 3-attempt retry with fixed delays.
func Retry(ctx context.Context, operation func() error) error {
	maxAttempts := 3
	delay := 2 * time.Second

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Check context before attempting
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Try the operation
		if err := operation(); err == nil {
			return nil // Success
		} else {
			lastErr = err
		}

		// Don't sleep after the last attempt
		if attempt < maxAttempts {
			select {
			case <-time.After(delay):
				// Continue to next attempt
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// Customize error message for authentication failures
	if lastErr != nil && strings.Contains(lastErr.Error(), "authentication denied") {
		// Extract the detail part after "authentication denied: "
		errMsg := lastErr.Error()
		if idx := strings.Index(errMsg, "authentication denied: "); idx >= 0 {
			detail := errMsg[idx+len("authentication denied: "):]
			return fmt.Errorf("authentication denied after %d attempts: %s", maxAttempts, detail)
		}
		return fmt.Errorf("authentication denied after %d attempts: %w", maxAttempts, lastErr)
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}

// RetryWithResult performs a simple retry for operations that return a value.
func RetryWithResult[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	maxAttempts := 3
	delay := 2 * time.Second

	var zero T
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Check context before attempting
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}

		// Try the operation
		result, err := operation()
		if err == nil {
			return result, nil // Success
		}
		lastErr = err

		// Don't sleep after the last attempt
		if attempt < maxAttempts {
			select {
			case <-time.After(delay):
				// Continue to next attempt
			case <-ctx.Done():
				return zero, ctx.Err()
			}
		}
	}

	// Customize error message for authentication failures
	if lastErr != nil && strings.Contains(lastErr.Error(), "authentication denied") {
		// Extract the detail part after "authentication denied: "
		errMsg := lastErr.Error()
		if idx := strings.Index(errMsg, "authentication denied: "); idx >= 0 {
			detail := errMsg[idx+len("authentication denied: "):]
			return zero, fmt.Errorf("authentication denied after %d attempts: %s", maxAttempts, detail)
		}
		return zero, fmt.Errorf("authentication denied after %d attempts: %w", maxAttempts, lastErr)
	}

	return zero, fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}
