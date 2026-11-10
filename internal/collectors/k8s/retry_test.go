package k8s

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryOnce(t *testing.T) {
	old := retryPause
	retryPause = 5 * time.Millisecond
	defer func() { retryPause = old }()

	t.Run("a read that works is made once", func(t *testing.T) {
		calls := 0
		v, err := retryOnce(t.Context(), func() (int, error) { calls++; return 7, nil })
		if v != 7 || err != nil || calls != 1 {
			t.Fatalf("v=%d err=%v calls=%d", v, err, calls)
		}
	})

	t.Run("a read that fails once is tried again, and the second answer stands", func(t *testing.T) {
		calls := 0
		v, err := retryOnce(t.Context(), func() (int, error) {
			calls++
			if calls == 1 {
				return 0, errors.New("connection reset")
			}
			return 9, nil
		})
		if v != 9 || err != nil || calls != 2 {
			t.Fatalf("v=%d err=%v calls=%d", v, err, calls)
		}
	})

	t.Run("a read that fails twice is a failure, and is not tried a third time", func(t *testing.T) {
		calls := 0
		_, err := retryOnce(t.Context(), func() (int, error) { calls++; return 0, errors.New("down") })
		if err == nil || calls != 2 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})

	t.Run("it waits before trying again", func(t *testing.T) {
		retryPause = 40 * time.Millisecond
		defer func() { retryPause = 5 * time.Millisecond }()
		var first, second time.Time
		_, _ = retryOnce(t.Context(), func() (int, error) {
			if first.IsZero() {
				first = time.Now()
				return 0, errors.New("blip")
			}
			second = time.Now()
			return 1, nil
		})
		if gap := second.Sub(first); gap < 35*time.Millisecond {
			t.Fatalf("retried after %v, want the pause", gap)
		}
	})

	t.Run("a collection that is being stopped does not wait or retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		calls := 0
		_, err := retryOnce(ctx, func() (int, error) { calls++; return 0, errors.New("blip") })
		if err == nil || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
}
