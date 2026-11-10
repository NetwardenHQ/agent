package k8s

import (
	"context"
	"time"
)

// retryPause is how long a failed read waits before its one retry: long
// enough for a reset connection or a brief network interruption to pass,
// short enough to stay well inside a collection round.
var retryPause = 2 * time.Second

// retryOnce runs read and, if it fails, waits retryPause and runs it once
// more. The second answer stands, whatever it is.
//
// It exists for reads whose failure is itself reported ("exporter
// unreachable", "kubelet unreachable"). Those reports are counted and alerted
// on, and a single lost request (a network interruption of a few seconds)
// should not read as a component nobody can reach.
func retryOnce[T any](ctx context.Context, read func() (T, error)) (T, error) {
	v, err := read()
	if err == nil {
		return v, nil
	}
	select {
	case <-ctx.Done():
		return v, err
	case <-time.After(retryPause):
	}
	return read()
}
