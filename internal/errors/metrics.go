package errors

import (
	"sync"
	"sync/atomic"
	"time"
)

// ErrorMetrics tracks error-related metrics
type ErrorMetrics struct {
	// Error counts by type
	errorCounts map[ErrorType]*atomic.Int64
	countsMu    sync.RWMutex

	// Error counts by severity
	severityCounts map[Severity]*atomic.Int64
	severityMu     sync.RWMutex

	// Recovery metrics
	recoveryCount   atomic.Int64
	retryCount      atomic.Int64
	maxRetriesCount atomic.Int64
	panicCount      atomic.Int64

	// Timing metrics
	lastErrorTime   atomic.Value // stores time.Time
	errorRate       atomic.Value // stores float64
	errorRateWindow time.Duration
	errorTimestamps []time.Time
	timestampsMu    sync.Mutex

	// Component error tracking
	componentErrors map[string]*atomic.Int64
	componentMu     sync.RWMutex
}

// NewErrorMetrics creates a new error metrics tracker
func NewErrorMetrics() *ErrorMetrics {
	em := &ErrorMetrics{
		errorCounts:     make(map[ErrorType]*atomic.Int64),
		severityCounts:  make(map[Severity]*atomic.Int64),
		componentErrors: make(map[string]*atomic.Int64),
		errorRateWindow: 1 * time.Minute,
		errorTimestamps: make([]time.Time, 0, 100),
	}

	// Initialize error type counters
	for i := ErrTypeUnknown; i <= ErrTypeInternal; i++ {
		em.errorCounts[i] = &atomic.Int64{}
	}

	// Initialize severity counters
	for i := SeverityLow; i <= SeverityCritical; i++ {
		em.severityCounts[i] = &atomic.Int64{}
	}

	// Initialize atomic values
	em.lastErrorTime.Store(time.Time{})
	em.errorRate.Store(float64(0))

	return em
}

// RecordError records an error occurrence
func (em *ErrorMetrics) RecordError(err error) {
	if err == nil {
		return
	}

	now := time.Now()
	em.lastErrorTime.Store(now)

	em.recordTimestamp(now)

	// Extract error metadata
	errType := GetErrorType(err)
	severity := GetSeverity(err)

	// Increment type counter
	em.countsMu.RLock()
	if counter, ok := em.errorCounts[errType]; ok {
		counter.Add(1)
	}
	em.countsMu.RUnlock()

	// Increment severity counter
	em.severityMu.RLock()
	if counter, ok := em.severityCounts[severity]; ok {
		counter.Add(1)
	}
	em.severityMu.RUnlock()

	if agentErr, ok := err.(*AgentError); ok && agentErr.Component != "" {
		em.recordComponentError(agentErr.Component)
	}
}

// RecordRecovery records a successful error recovery
func (em *ErrorMetrics) RecordRecovery(err error) {
	em.recoveryCount.Add(1)
}

// RecordRetry records a retry attempt
func (em *ErrorMetrics) RecordRetry(err error) {
	em.retryCount.Add(1)
}

// RecordMaxRetriesExceeded records when max retries are exceeded
func (em *ErrorMetrics) RecordMaxRetriesExceeded(err error) {
	em.maxRetriesCount.Add(1)
}

// RecordPanic records a panic occurrence
func (em *ErrorMetrics) RecordPanic() {
	em.panicCount.Add(1)
}

func (em *ErrorMetrics) GetErrorCount(errType ErrorType) int64 {
	em.countsMu.RLock()
	defer em.countsMu.RUnlock()

	if counter, ok := em.errorCounts[errType]; ok {
		return counter.Load()
	}
	return 0
}

func (em *ErrorMetrics) GetSeverityCount(severity Severity) int64 {
	em.severityMu.RLock()
	defer em.severityMu.RUnlock()

	if counter, ok := em.severityCounts[severity]; ok {
		return counter.Load()
	}
	return 0
}

func (em *ErrorMetrics) GetComponentErrorCount(component string) int64 {
	em.componentMu.RLock()
	defer em.componentMu.RUnlock()

	if counter, ok := em.componentErrors[component]; ok {
		return counter.Load()
	}
	return 0
}

func (em *ErrorMetrics) GetErrorRate() float64 {
	em.timestampsMu.Lock()
	defer em.timestampsMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-em.errorRateWindow)

	i := 0
	for i < len(em.errorTimestamps) && em.errorTimestamps[i].Before(cutoff) {
		i++
	}
	em.errorTimestamps = em.errorTimestamps[i:]

	// Calculate rate
	if len(em.errorTimestamps) == 0 {
		em.errorRate.Store(float64(0))
		return 0
	}

	rate := float64(len(em.errorTimestamps)) / em.errorRateWindow.Minutes()
	em.errorRate.Store(rate)
	return rate
}

func (em *ErrorMetrics) GetStats() ErrorStats {
	stats := ErrorStats{
		ErrorsByType:      make(map[ErrorType]int64),
		ErrorsBySeverity:  make(map[Severity]int64),
		ErrorsByComponent: make(map[string]int64),
		RecoveryCount:     em.recoveryCount.Load(),
		RetryCount:        em.retryCount.Load(),
		MaxRetriesCount:   em.maxRetriesCount.Load(),
		PanicCount:        em.panicCount.Load(),
		ErrorRate:         em.GetErrorRate(),
	}

	if t, ok := em.lastErrorTime.Load().(time.Time); ok && !t.IsZero() {
		stats.LastErrorTime = t
	}

	// Collect error counts by type
	em.countsMu.RLock()
	for errType, counter := range em.errorCounts {
		if count := counter.Load(); count > 0 {
			stats.ErrorsByType[errType] = count
			stats.TotalErrors += count
		}
	}
	em.countsMu.RUnlock()

	// Collect error counts by severity
	em.severityMu.RLock()
	for severity, counter := range em.severityCounts {
		if count := counter.Load(); count > 0 {
			stats.ErrorsBySeverity[severity] = count
		}
	}
	em.severityMu.RUnlock()

	// Collect component errors
	em.componentMu.RLock()
	for component, counter := range em.componentErrors {
		if count := counter.Load(); count > 0 {
			stats.ErrorsByComponent[component] = count
		}
	}
	em.componentMu.RUnlock()

	// Calculate recovery rate
	if stats.TotalErrors > 0 {
		stats.RecoveryRate = float64(stats.RecoveryCount) / float64(stats.TotalErrors) * 100
	}

	// Calculate retry success rate
	if stats.RetryCount > 0 {
		successfulRetries := stats.RecoveryCount
		stats.RetrySuccessRate = float64(successfulRetries) / float64(stats.RetryCount) * 100
	}

	return stats
}

// Reset resets all metrics
func (em *ErrorMetrics) Reset() {
	// Reset error type counts
	em.countsMu.Lock()
	for _, counter := range em.errorCounts {
		counter.Store(0)
	}
	em.countsMu.Unlock()

	// Reset severity counts
	em.severityMu.Lock()
	for _, counter := range em.severityCounts {
		counter.Store(0)
	}
	em.severityMu.Unlock()

	// Reset component errors
	em.componentMu.Lock()
	em.componentErrors = make(map[string]*atomic.Int64)
	em.componentMu.Unlock()

	// Reset other metrics
	em.recoveryCount.Store(0)
	em.retryCount.Store(0)
	em.maxRetriesCount.Store(0)
	em.panicCount.Store(0)
	em.lastErrorTime.Store(time.Time{})
	em.errorRate.Store(float64(0))

	// Clear timestamps
	em.timestampsMu.Lock()
	em.errorTimestamps = em.errorTimestamps[:0]
	em.timestampsMu.Unlock()
}

// recordTimestamp records an error timestamp for rate calculation
func (em *ErrorMetrics) recordTimestamp(t time.Time) {
	em.timestampsMu.Lock()
	defer em.timestampsMu.Unlock()

	em.errorTimestamps = append(em.errorTimestamps, t)

	// Limit size to prevent unbounded growth
	if len(em.errorTimestamps) > 1000 {
		// Keep the most recent 500
		em.errorTimestamps = em.errorTimestamps[len(em.errorTimestamps)-500:]
	}
}

// recordComponentError records an error for a component
func (em *ErrorMetrics) recordComponentError(component string) {
	em.componentMu.Lock()
	defer em.componentMu.Unlock()

	if counter, ok := em.componentErrors[component]; ok {
		counter.Add(1)
	} else {
		newCounter := &atomic.Int64{}
		newCounter.Store(1)
		em.componentErrors[component] = newCounter
	}
}

// ErrorStats represents error statistics
type ErrorStats struct {
	TotalErrors       int64
	ErrorsByType      map[ErrorType]int64
	ErrorsBySeverity  map[Severity]int64
	ErrorsByComponent map[string]int64
	RecoveryCount     int64
	RecoveryRate      float64
	RetryCount        int64
	RetrySuccessRate  float64
	MaxRetriesCount   int64
	PanicCount        int64
	ErrorRate         float64
	LastErrorTime     time.Time
}

func (es *ErrorStats) GetTopErrors(limit int) []ErrorTypeStat {
	result := make([]ErrorTypeStat, 0, len(es.ErrorsByType))

	for errType, count := range es.ErrorsByType {
		result = append(result, ErrorTypeStat{
			Type:  errType,
			Count: count,
		})
	}

	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[i].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}

	return result
}

// ErrorTypeStat represents statistics for an error type
type ErrorTypeStat struct {
	Type  ErrorType
	Count int64
}

func (es *ErrorStats) GetCriticalErrorCount() int64 {
	return es.ErrorsBySeverity[SeverityCritical]
}

func (es *ErrorStats) HasCriticalErrors() bool {
	return es.GetCriticalErrorCount() > 0
}

func GetErrorTypeName(errType ErrorType) string {
	switch errType {
	case ErrTypeUnknown:
		return "Unknown"
	case ErrTypeNetwork:
		return "Network"
	case ErrTypeTimeout:
		return "Timeout"
	case ErrTypeRateLimit:
		return "RateLimit"
	case ErrTypeAuth:
		return "Authentication"
	case ErrTypeConfig:
		return "Configuration"
	case ErrTypeValidation:
		return "Validation"
	case ErrTypeResource:
		return "Resource"
	case ErrTypeInternal:
		return "Internal"
	default:
		return "Other"
	}
}

func GetSeverityName(severity Severity) string {
	switch severity {
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}
