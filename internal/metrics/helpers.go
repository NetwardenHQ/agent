// Package metrics provides simplified metric creation helpers.
package metrics

import "time"

// QuickGauge creates a gauge metric with minimal parameters.
func QuickGauge(hostname, name string, value float64) Metric {
	return Metric{
		Name:      name,
		Value:     value,
		Type:      MetricTypeGauge,
		Timestamp: time.Now(),
		Labels:    map[string]string{"host": hostname},
	}
}

// QuickGaugeWithLabels creates a gauge metric with labels.
func QuickGaugeWithLabels(hostname, name string, value float64, labels map[string]string) Metric {
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["host"] = hostname
	return Metric{
		Name:      name,
		Value:     value,
		Type:      MetricTypeGauge,
		Timestamp: time.Now(),
		Labels:    labels,
	}
}

// QuickCounter creates a counter metric with minimal parameters.
func QuickCounter(hostname, name string, value float64) Metric {
	return Metric{
		Name:      name,
		Value:     value,
		Type:      MetricTypeCounter,
		Timestamp: time.Now(),
		Labels:    map[string]string{"host": hostname},
	}
}
