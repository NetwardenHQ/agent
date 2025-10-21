// Package metrics provides delta compression for efficient metric transmission.
package metrics

import (
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// DeltaTracker tracks metric changes and determines which metrics should be transmitted
// based on configurable change thresholds and time-based fallbacks.
type DeltaTracker struct {
	previous        map[string]*MetricState
	mu              sync.RWMutex
	threshold       float64       // Percentage change threshold (e.g., 1.0 = 1%)
	maxAge          time.Duration // Maximum time before forcing transmission
	maxEntries      int           // Maximum number of entries to track
	cleanupInterval time.Duration // Cleanup interval
	logger          *slog.Logger

	// Statistics for monitoring
	totalMetrics   int64
	sentMetrics    int64
	skippedMetrics int64
	evictedEntries int64
	statsMu        sync.RWMutex
}

// MetricState represents the previous state of a metric for delta comparison.
type MetricState struct {
	Value        float64
	Timestamp    time.Time
	LastSent     time.Time
	LastAccessed time.Time // For LRU eviction
	Type         MetricType
	Labels       map[string]string
	SendCount    int64 // Number of times this metric has been sent
}

// DeltaConfig configures the delta compression behavior.
type DeltaConfig struct {
	// Threshold is the percentage change required to trigger transmission (default: 1.0%)
	Threshold float64

	// MaxAge is the maximum time before forcing transmission (default: 5 minutes)
	MaxAge time.Duration

	// Enabled controls whether delta compression is active (default: true)
	Enabled bool

	// MaxEntries is the maximum number of metric states to track (default: 10,000)
	// When exceeded, least recently used entries are evicted
	MaxEntries int

	// CleanupInterval is how often to run cleanup of old entries (default: 1 hour)
	CleanupInterval time.Duration

	// Logger for debug and monitoring information
	Logger *slog.Logger
}

// NewDeltaTracker creates a new delta compression tracker with the specified configuration.
func NewDeltaTracker(config DeltaConfig) *DeltaTracker {
	// Set defaults
	if config.Threshold <= 0 {
		config.Threshold = 1.0 // 1% default
	}
	if config.MaxAge <= 0 {
		config.MaxAge = 5 * time.Minute // 5 minutes default
	}
	if config.MaxEntries <= 0 {
		config.MaxEntries = 10000 // 10,000 entries default
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 1 * time.Hour // 1 hour default
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &DeltaTracker{
		previous:        make(map[string]*MetricState),
		threshold:       config.Threshold,
		maxAge:          config.MaxAge,
		maxEntries:      config.MaxEntries,
		cleanupInterval: config.CleanupInterval,
		logger:          config.Logger.With("component", "delta_tracker"),
	}
}

// evictLRU removes the least recently used entries when the maximum capacity is exceeded.
// This method assumes the mutex is already held by the caller.
func (dt *DeltaTracker) evictLRU() {
	if len(dt.previous) <= dt.maxEntries {
		return // No eviction needed
	}

	// Calculate how many entries to evict (evict 10% when limit is hit)
	evictCount := len(dt.previous) - dt.maxEntries + (dt.maxEntries / 10)
	if evictCount <= 0 {
		return
	}

	// Find the oldest entries by LastAccessed time
	type entry struct {
		key        string
		lastAccess time.Time
	}

	entries := make([]entry, 0, len(dt.previous))
	for key, state := range dt.previous {
		entries = append(entries, entry{key: key, lastAccess: state.LastAccessed})
	}

	// Sort by LastAccessed time (oldest first) - using efficient stdlib sort
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastAccess.Before(entries[j].lastAccess)
	})

	// Remove the oldest entries
	evicted := 0
	for i := 0; i < len(entries) && evicted < evictCount; i++ {
		delete(dt.previous, entries[i].key)
		evicted++
	}

	// Update statistics
	dt.statsMu.Lock()
	dt.evictedEntries += int64(evicted)
	dt.statsMu.Unlock()

	dt.logger.Debug("Evicted LRU entries from delta tracker",
		"evicted_count", evicted,
		"remaining_entries", len(dt.previous),
		"max_entries", dt.maxEntries)
}

// ShouldSend determines if a metric should be transmitted based on delta compression rules.
// Returns true if the metric should be sent, false if it can be skipped.
func (dt *DeltaTracker) ShouldSend(metric Metric) bool {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.statsMu.Lock()
	dt.totalMetrics++
	dt.statsMu.Unlock()

	// Create a unique key for this metric (name + labels)
	key := dt.createMetricKey(metric)
	now := time.Now()

	previous, exists := dt.previous[key]

	// Always send if this is the first time we've seen this metric
	if !exists {
		dt.updateMetricState(key, metric, now)
		dt.recordSent()
		dt.logger.Debug("First time metric - sending",
			"metric", metric.Name,
			"value", metric.Value)
		return true
	}

	// Always send if metric type changed (shouldn't happen in practice)
	if previous.Type != metric.Type {
		dt.updateMetricState(key, metric, now)
		dt.recordSent()
		dt.logger.Debug("Metric type changed - sending",
			"metric", metric.Name,
			"old_type", previous.Type,
			"new_type", metric.Type)
		return true
	}

	// Force send if too much time has passed since last transmission
	timeSinceLastSent := now.Sub(previous.LastSent)
	if timeSinceLastSent > dt.maxAge {
		dt.updateMetricState(key, metric, now)
		dt.recordSent()
		dt.logger.Debug("Max age exceeded - sending",
			"metric", metric.Name,
			"time_since_last", timeSinceLastSent,
			"max_age", dt.maxAge)
		return true
	}

	// For counters, always send if value increased (counters should only go up)
	if metric.Type == MetricTypeCounter && metric.Value > previous.Value {
		dt.updateMetricState(key, metric, now)
		dt.recordSent()
		dt.logger.Debug("Counter increased - sending",
			"metric", metric.Name,
			"old_value", previous.Value,
			"new_value", metric.Value)
		return true
	}

	// For gauges and histograms, check percentage change
	if dt.hasSignificantChange(previous.Value, metric.Value) {
		dt.updateMetricState(key, metric, now)
		dt.recordSent()

		percentChange := dt.calculatePercentChange(previous.Value, metric.Value)
		dt.logger.Debug("Significant change detected - sending",
			"metric", metric.Name,
			"old_value", previous.Value,
			"new_value", metric.Value,
			"percent_change", percentChange,
			"threshold", dt.threshold)
		return true
	}

	// Update state but don't send
	dt.updateMetricStateNoSend(key, metric, now)
	dt.recordSkipped()

	dt.logger.Debug("Skipping metric - no significant change",
		"metric", metric.Name,
		"old_value", previous.Value,
		"new_value", metric.Value,
		"time_since_last_sent", timeSinceLastSent)

	return false
}

// FilterMetrics applies delta compression to a slice of metrics, returning only those that should be sent.
func (dt *DeltaTracker) FilterMetrics(metrics []Metric) []Metric {
	if len(metrics) == 0 {
		return metrics
	}

	var filtered []Metric
	for _, metric := range metrics {
		if dt.ShouldSend(metric) {
			filtered = append(filtered, metric)
		}
	}

	dt.logger.Debug("Delta compression applied",
		"input_count", len(metrics),
		"output_count", len(filtered),
		"compression_ratio", float64(len(filtered))/float64(len(metrics)))

	return filtered
}

// createMetricKey creates a unique key for a metric based on its name and labels.
// Uses efficient string building and deterministic label ordering.
func (dt *DeltaTracker) createMetricKey(metric Metric) string {
	if len(metric.Labels) == 0 {
		return metric.Name
	}

	// Create sorted list of label pairs for deterministic key generation
	labelPairs := make([]string, 0, len(metric.Labels))
	for k, v := range metric.Labels {
		labelPairs = append(labelPairs, k+"="+v)
	}
	sort.Strings(labelPairs)

	// Use strings.Builder for efficient string construction
	var builder strings.Builder
	builder.Grow(len(metric.Name) + 2 + len(labelPairs)*20) // Pre-allocate approximate capacity
	builder.WriteString(metric.Name)
	builder.WriteString("{")
	for i, pair := range labelPairs {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(pair)
	}
	builder.WriteString("}")

	return builder.String()
}

// hasSignificantChange determines if the change between two values exceeds the threshold.
func (dt *DeltaTracker) hasSignificantChange(oldValue, newValue float64) bool {
	// Handle zero values specially
	if oldValue == 0 {
		// If old value was 0 and new value is non-zero, that's significant
		return newValue != 0
	}

	percentChange := dt.calculatePercentChange(oldValue, newValue)
	return math.Abs(percentChange) >= dt.threshold
}

// calculatePercentChange calculates the percentage change between two values.
func (dt *DeltaTracker) calculatePercentChange(oldValue, newValue float64) float64 {
	if oldValue == 0 {
		if newValue == 0 {
			return 0
		}
		return 100 // Treat zero to non-zero as 100% change
	}

	return ((newValue - oldValue) / math.Abs(oldValue)) * 100
}

// updateMetricState updates the stored state for a metric and marks it as sent.
// Note: This method assumes dt.mu is already locked by the caller.
func (dt *DeltaTracker) updateMetricState(key string, metric Metric, now time.Time) {
	// Copy labels efficiently
	newLabels := make(map[string]string, len(metric.Labels))
	for k, v := range metric.Labels {
		newLabels[k] = v
	}

	// Determine send count
	sendCount := int64(1)
	if prev, exists := dt.previous[key]; exists {
		sendCount = prev.SendCount + 1
	}

	state := &MetricState{
		Value:        metric.Value,
		Timestamp:    now,
		LastSent:     now,
		LastAccessed: now,
		Type:         metric.Type,
		Labels:       newLabels,
		SendCount:    sendCount,
	}

	dt.previous[key] = state

	// Check if eviction is needed
	dt.evictLRU()
}

// updateMetricStateNoSend updates the stored state for a metric without marking it as sent.
// Note: This method assumes dt.mu is already locked by the caller.
func (dt *DeltaTracker) updateMetricStateNoSend(key string, metric Metric, now time.Time) {
	state, exists := dt.previous[key]
	if !exists {
		// This shouldn't happen, but handle it gracefully
		dt.logger.Warn("Attempted to update non-existent metric state", "key", key)
		return
	}

	// Update values atomically
	state.Value = metric.Value
	state.Timestamp = now
	state.LastAccessed = now // Update access time for LRU
	// Don't update LastSent - keep the previous send time

	// Update labels if they changed - create new map to avoid mutation issues
	if len(metric.Labels) != len(state.Labels) || !dt.labelsEqual(state.Labels, metric.Labels) {
		newLabels := make(map[string]string, len(metric.Labels))
		for k, v := range metric.Labels {
			newLabels[k] = v
		}
		state.Labels = newLabels
	}

	// Check if eviction is needed when adding new entries
	dt.evictLRU()
}

// labelsEqual compares two label maps for equality.
func (dt *DeltaTracker) labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, exists := b[k]; !exists || bv != v {
			return false
		}
	}
	return true
}

// recordSent increments the sent metrics counter.
func (dt *DeltaTracker) recordSent() {
	dt.statsMu.Lock()
	dt.sentMetrics++
	dt.statsMu.Unlock()
}

// recordSkipped increments the skipped metrics counter.
func (dt *DeltaTracker) recordSkipped() {
	dt.statsMu.Lock()
	dt.skippedMetrics++
	dt.statsMu.Unlock()
}

// Cleanup removes old metric states that haven't been updated recently to prevent memory leaks.
func (dt *DeltaTracker) Cleanup(maxAge time.Duration) int {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	if maxAge <= 0 {
		maxAge = 24 * time.Hour // Default: clean up metrics not seen in 24 hours
	}

	now := time.Now()
	removed := 0

	for key, state := range dt.previous {
		if now.Sub(state.Timestamp) > maxAge {
			delete(dt.previous, key)
			removed++
		}
	}

	if removed > 0 {
		dt.logger.Info("Cleaned up old metric states",
			"removed_count", removed,
			"remaining_count", len(dt.previous),
			"max_age", maxAge)
	}

	return removed
}

// GetStats returns statistics about delta compression performance.
func (dt *DeltaTracker) GetStats() DeltaStats {
	dt.statsMu.RLock()
	defer dt.statsMu.RUnlock()

	var compressionRatio float64
	if dt.totalMetrics > 0 {
		compressionRatio = float64(dt.sentMetrics) / float64(dt.totalMetrics)
	}

	dt.mu.RLock()
	trackedMetrics := len(dt.previous)
	dt.mu.RUnlock()

	return DeltaStats{
		TotalMetrics:     dt.totalMetrics,
		SentMetrics:      dt.sentMetrics,
		SkippedMetrics:   dt.skippedMetrics,
		CompressionRatio: compressionRatio,
		TrackedMetrics:   int64(trackedMetrics),
		Threshold:        dt.threshold,
		MaxAge:           dt.maxAge,
	}
}

// DeltaStats provides statistics about delta compression performance.
type DeltaStats struct {
	TotalMetrics     int64         // Total metrics processed
	SentMetrics      int64         // Metrics that were sent
	SkippedMetrics   int64         // Metrics that were skipped
	CompressionRatio float64       // Ratio of sent to total (lower is better compression)
	TrackedMetrics   int64         // Number of unique metrics being tracked
	Threshold        float64       // Current change threshold
	MaxAge           time.Duration // Current max age before forced send
}

// Reset clears all tracking state and statistics.
func (dt *DeltaTracker) Reset() {
	dt.mu.Lock()
	dt.statsMu.Lock()
	defer dt.mu.Unlock()
	defer dt.statsMu.Unlock()

	dt.previous = make(map[string]*MetricState)
	dt.totalMetrics = 0
	dt.sentMetrics = 0
	dt.skippedMetrics = 0

	dt.logger.Info("Delta tracker reset - all state cleared")
}
