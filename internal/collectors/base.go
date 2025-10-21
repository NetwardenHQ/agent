// Package collectors provides common base functionality for all metric collectors.
package collectors

import (
	"context"
	"log/slog"
	"time"

	"netwarden/internal/metrics"
)

// BaseCollector provides common functionality for all collectors.
type BaseCollector struct {
	// Core fields every collector needs
	Logger   *slog.Logger
	Hostname string
	Builder  metrics.MetricBuilder

	// Common configuration
	Enabled  bool
	Interval time.Duration
	Name     string
}

// NewBaseCollector creates a new base collector with common initialization.
func NewBaseCollector(name string, hostname string, enabled bool, logger *slog.Logger) BaseCollector {
	if logger == nil {
		logger = slog.Default()
	}

	return BaseCollector{
		Logger:   logger.With("collector", name),
		Hostname: hostname,
		Builder:  metrics.NewBuilder().WithHostname(hostname),
		Enabled:  enabled,
		Interval: 60 * time.Second,
		Name:     name,
	}
}

func (b *BaseCollector) CollectorName() string {
	return b.Name
}

func (b *BaseCollector) IsEnabled() bool {
	return b.Enabled
}

func (b *BaseCollector) LogDebug(msg string, args ...any) {
	b.Logger.Debug(msg, args...)
}

func (b *BaseCollector) LogInfo(msg string, args ...any) {
	b.Logger.Info(msg, args...)
}

func (b *BaseCollector) LogWarn(msg string, args ...any) {
	b.Logger.Warn(msg, args...)
}

func (b *BaseCollector) LogError(msg string, args ...any) {
	b.Logger.Error(msg, args...)
}

func (b *BaseCollector) WithTimestamp(t time.Time) {
	b.Builder = b.Builder.WithTimestamp(t)
}

// CollectWithTimeout runs a collection function with a timeout.
func (b *BaseCollector) CollectWithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn(ctx)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		b.LogWarn("collection timed out", "timeout", timeout)
		return ctx.Err()
	}
}

// HandleError logs an error and decides whether to continue or fail collection.
func (b *BaseCollector) HandleError(err error, msg string, critical bool) error {
	if err == nil {
		return nil
	}

	if critical {
		b.LogError(msg, "error", err)
		return err
	}

	b.LogWarn(msg, "error", err)
	return nil
}

// BuildGaugeMetric creates a gauge metric using the correct MetricBuilder pattern.
func (b *BaseCollector) BuildGaugeMetric(name string, value float64, labels map[string]string) (metrics.Metric, error) {
	return b.Builder.WithTimestamp(time.Now()).GaugeWithLabels(name, value, labels)
}

// BuildCounterMetric creates a counter metric using the correct MetricBuilder pattern.
func (b *BaseCollector) BuildCounterMetric(name string, value float64, labels map[string]string) (metrics.Metric, error) {
	return b.Builder.WithTimestamp(time.Now()).CounterWithLabels(name, value, labels)
}
