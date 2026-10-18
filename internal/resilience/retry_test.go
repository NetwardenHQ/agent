package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_StopsOnPermanentError(t *testing.T) {
	calls := 0
	denied := errors.New("authentication denied")
	err := Retry(context.Background(), func() error {
		calls++
		return Permanent(denied)
	})
	if calls != 1 {
		t.Fatalf("a permanent error must not be retried; got %d calls", calls)
	}
	if !errors.Is(err, denied) {
		t.Fatalf("expected the underlying error, got %v", err)
	}
}

func TestRetry_HonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	start := time.Now()
	err := Retry(ctx, func() error {
		calls++
		cancel()
		return errors.New("transient")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 1 || time.Since(start) > retryDelay {
		t.Fatalf("cancellation must end the retry loop immediately (calls=%d)", calls)
	}
}

func TestRetry_SucceedsAfterTransientFailure(t *testing.T) {
	t.Parallel()
	calls := 0
	err := Retry(context.Background(), func() error {
		calls++
		if calls < 2 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("expected success on the second attempt, got err=%v calls=%d", err, calls)
	}
}
