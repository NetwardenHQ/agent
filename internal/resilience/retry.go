// Package resilience provides retry logic for network operations.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	maxAttempts = 3
	retryDelay  = 2 * time.Second
)

// PermanentError marks a failure that retrying cannot fix, such as a rejected
// credential or a payload the server refuses. Retry returns it at once.
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps err so Retry stops on it.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// Retry runs operation up to three times with a fixed delay between
// attempts. It stops early on a PermanentError or when ctx is done. The
// returned error wraps the last failure.
func Retry(ctx context.Context, operation func() error) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := operation()
		if err == nil {
			return nil
		}
		lastErr = err

		var permanent *PermanentError
		if errors.As(err, &permanent) {
			return permanent.Err
		}

		if attempt < maxAttempts {
			timer := time.NewTimer(retryDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
	}
	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}
