// Package metrics provides metric building functionality.
package metrics

import (
	"time"
)

// Builder provides methods for creating metrics.
type Builder struct {
	hostname  string
	timestamp time.Time
}

// NewBuilder creates a new metric builder.
func NewBuilder() MetricBuilder {
	return &Builder{
		timestamp: time.Now(),
	}
}

// MetricBuilder interface for building metrics.
type MetricBuilder interface {
	WithHostname(hostname string) MetricBuilder
	WithTimestamp(timestamp time.Time) MetricBuilder
	Gauge(name string, value float64) (Metric, error)
	GaugeWithLabels(name string, value float64, labels map[string]string) (Metric, error)
	Counter(name string, value float64) (Metric, error)
	CounterWithLabels(name string, value float64, labels map[string]string) (Metric, error)
}

// WithHostname sets the hostname for metrics.
func (b *Builder) WithHostname(hostname string) MetricBuilder {
	b.hostname = hostname
	return b
}

// WithTimestamp sets the timestamp for metrics.
func (b *Builder) WithTimestamp(timestamp time.Time) MetricBuilder {
	b.timestamp = timestamp
	return b
}

// Gauge creates a gauge metric.
func (b *Builder) Gauge(name string, value float64) (Metric, error) {
	return b.GaugeWithLabels(name, value, nil)
}

// GaugeWithLabels creates a gauge metric with labels.
func (b *Builder) GaugeWithLabels(name string, value float64, labels map[string]string) (Metric, error) {
	if labels == nil {
		labels = make(map[string]string)
	}

	if b.hostname != "" {
		labels["host"] = b.hostname
	}

	return Metric{
		Name:      name,
		Value:     value,
		Type:      MetricTypeGauge,
		Timestamp: b.timestamp,
		Labels:    labels,
	}, nil
}

// Counter creates a counter metric.
func (b *Builder) Counter(name string, value float64) (Metric, error) {
	return b.CounterWithLabels(name, value, nil)
}

// CounterWithLabels creates a counter metric with labels.
func (b *Builder) CounterWithLabels(name string, value float64, labels map[string]string) (Metric, error) {
	if labels == nil {
		labels = make(map[string]string)
	}

	if b.hostname != "" {
		labels["host"] = b.hostname
	}

	return Metric{
		Name:      name,
		Value:     value,
		Type:      MetricTypeCounter,
		Timestamp: b.timestamp,
		Labels:    labels,
	}, nil
}
