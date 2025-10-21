// Package pool provides concurrent collection with worker pool pattern.
package pool

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"netwarden/internal/metrics"
)

// CollectorTask represents a collection task for a specific collector.
type CollectorTask struct {
	Collector metrics.Collector
	Timeout   time.Duration
}

// CollectorResult represents the result of a collection task.
type CollectorResult struct {
	CollectorName string
	Metrics       []metrics.Metric
	Duration      time.Duration
	Error         error
}

// WorkerPoolConfig configures the collector worker pool.
type WorkerPoolConfig struct {
	// NumWorkers is the number of concurrent workers.
	// Default: min(runtime.NumCPU(), 3)
	NumWorkers int

	// TaskQueueSize is the size of the task queue buffer.
	// Default: 50
	TaskQueueSize int

	// DefaultTaskTimeout is the default timeout for individual collection tasks.
	// Default: 10 seconds
	DefaultTaskTimeout time.Duration

	// Logger for debug and monitoring information.
	Logger *slog.Logger
}

// DefaultWorkerPoolConfig returns a worker pool configuration with sensible defaults.
func DefaultWorkerPoolConfig() WorkerPoolConfig {
	// Limit workers to maximum of 3 for better resource efficiency
	numWorkers := runtime.NumCPU()
	if numWorkers > 3 {
		numWorkers = 3
	}

	return WorkerPoolConfig{
		NumWorkers:         numWorkers,
		TaskQueueSize:      50,
		DefaultTaskTimeout: 10 * time.Second,
		Logger:             slog.Default().With("component", "worker_pool"),
	}
}

// WorkerPool manages concurrent collection tasks.
type WorkerPool struct {
	config    WorkerPoolConfig
	taskQueue chan CollectorTask
	results   chan CollectorResult
	wg        sync.WaitGroup
	mu        sync.RWMutex
	started   bool
	stopped   bool
	logger    *slog.Logger
}

// NewWorkerPool creates a new worker pool with the given configuration.
func NewWorkerPool(config WorkerPoolConfig) *WorkerPool {
	// Apply defaults for zero values
	if config.NumWorkers <= 0 {
		config.NumWorkers = DefaultWorkerPoolConfig().NumWorkers
	}
	if config.TaskQueueSize <= 0 {
		config.TaskQueueSize = DefaultWorkerPoolConfig().TaskQueueSize
	}
	if config.DefaultTaskTimeout <= 0 {
		config.DefaultTaskTimeout = DefaultWorkerPoolConfig().DefaultTaskTimeout
	}
	if config.Logger == nil {
		config.Logger = slog.Default().With("component", "worker_pool")
	}

	return &WorkerPool{
		config:    config,
		taskQueue: make(chan CollectorTask, config.TaskQueueSize),
		results:   make(chan CollectorResult, config.TaskQueueSize),
		logger:    config.Logger,
	}
}

// Start initializes and starts the worker pool.
func (wp *WorkerPool) Start(ctx context.Context) error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.started {
		return fmt.Errorf("worker pool already started")
	}
	if wp.stopped {
		return fmt.Errorf("worker pool already stopped, create a new instance")
	}

	wp.started = true

	// Start workers
	for i := 0; i < wp.config.NumWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}

	wp.logger.Info("worker pool started",
		"workers", wp.config.NumWorkers,
		"queue_size", wp.config.TaskQueueSize)

	return nil
}

// worker processes tasks from the queue.
func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	wp.logger.Debug("worker started", "worker_id", id)

	for {
		select {
		case <-ctx.Done():
			wp.logger.Debug("worker stopping", "worker_id", id)
			return

		case task, ok := <-wp.taskQueue:
			if !ok {
				wp.logger.Debug("task queue closed, worker stopping", "worker_id", id)
				return
			}

			result := wp.executeTask(ctx, task)

			select {
			case wp.results <- result:
				// Result sent
			case <-ctx.Done():
				return
			}
		}
	}
}

// executeTask executes a single collection task.
func (wp *WorkerPool) executeTask(ctx context.Context, task CollectorTask) CollectorResult {
	startTime := time.Now()

	// Apply timeout if specified
	taskCtx := ctx
	var cancel context.CancelFunc
	if task.Timeout > 0 {
		taskCtx, cancel = context.WithTimeout(ctx, task.Timeout)
	} else if wp.config.DefaultTaskTimeout > 0 {
		taskCtx, cancel = context.WithTimeout(ctx, wp.config.DefaultTaskTimeout)
	}
	if cancel != nil {
		defer cancel()
	}

	// Collect metrics
	collectedMetrics, err := task.Collector.Collect(taskCtx)

	duration := time.Since(startTime)

	return CollectorResult{
		CollectorName: task.Collector.Name(),
		Metrics:       collectedMetrics,
		Duration:      duration,
		Error:         err,
	}
}

// Submit adds a collection task to the pool.
func (wp *WorkerPool) Submit(task CollectorTask) error {
	wp.mu.RLock()
	if !wp.started {
		wp.mu.RUnlock()
		return fmt.Errorf("worker pool not started")
	}
	if wp.stopped {
		wp.mu.RUnlock()
		return fmt.Errorf("worker pool stopped")
	}
	wp.mu.RUnlock()

	select {
	case wp.taskQueue <- task:
		return nil
	default:
		return fmt.Errorf("task queue is full")
	}
}

// CollectAll submits all collectors and waits for results.
func (wp *WorkerPool) CollectAll(ctx context.Context, collectors []metrics.Collector) []CollectorResult {
	var results []CollectorResult
	var submittedCount int

	// Submit all tasks
	for _, collector := range collectors {
		if !collector.Enabled() {
			continue
		}

		task := CollectorTask{
			Collector: collector,
			Timeout:   wp.config.DefaultTaskTimeout,
		}

		if err := wp.Submit(task); err != nil {
			wp.logger.Error("failed to submit task",
				"collector", collector.Name(),
				"error", err)
			results = append(results, CollectorResult{
				CollectorName: collector.Name(),
				Error:         err,
			})
		} else {
			submittedCount++
		}
	}

	// Collect results with platform-aware timeout
	// Windows needs more time for COM/WMI initialization overhead
	// Linux uses fast /proc filesystem and completes quickly
	var overallTimeout time.Duration
	if runtime.GOOS == "windows" {
		overallTimeout = 40 * time.Second // Windows: COM + WMI overhead
	} else {
		overallTimeout = 30 * time.Second // Linux: Fast /proc filesystem
	}

	resultTimeout := time.NewTimer(overallTimeout)
	defer resultTimeout.Stop()

	expectedResults := submittedCount
	for i := 0; i < expectedResults; i++ {
		select {
		case result := <-wp.results:
			results = append(results, result)

		case <-resultTimeout.C:
			// Extract completed collector names for debugging
			completedNames := make([]string, 0, len(results))
			for _, r := range results {
				completedNames = append(completedNames, r.CollectorName)
			}

			wp.logger.Error("COLLECTION TIMEOUT - Agent may appear offline",
				"received", len(results),
				"expected", expectedResults,
				"timeout_seconds", overallTimeout.Seconds(),
				"completed_collectors", completedNames,
				"platform", runtime.GOOS)
			return results

		case <-ctx.Done():
			return results
		}
	}

	return results
}

// Stop gracefully shuts down the worker pool.
func (wp *WorkerPool) Stop(ctx context.Context) error {
	wp.mu.Lock()
	if wp.stopped {
		wp.mu.Unlock()
		return nil
	}
	wp.stopped = true
	wp.mu.Unlock()

	// Close task queue to signal workers to stop
	close(wp.taskQueue)

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		wp.logger.Info("worker pool stopped gracefully")
		return nil
	case <-ctx.Done():
		wp.logger.Warn("worker pool stop timeout")
		return fmt.Errorf("timeout waiting for workers to stop")
	}
}

// GetQueueSize returns the current number of tasks in the queue.
func (wp *WorkerPool) GetQueueSize() int {
	return len(wp.taskQueue)
}

// GetResultsSize returns the current number of results waiting to be processed.
func (wp *WorkerPool) GetResultsSize() int {
	return len(wp.results)
}
