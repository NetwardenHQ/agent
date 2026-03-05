// Package postgresql provides PostgreSQL metrics collection for the Netwarden agent.
package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

// pgCache provides caching for PostgreSQL stats to reduce query load.
type pgCache struct {
	stats    map[string]interface{}
	cachedAt time.Time
	ttl      time.Duration
	mutex    sync.RWMutex
}

// newPGCache creates a new PostgreSQL cache with 30-second TTL.
func newPGCache() *pgCache {
	return &pgCache{
		ttl:   30 * time.Second,
		stats: make(map[string]interface{}),
	}
}

// get retrieves cached stats if they're still valid.
func (c *pgCache) get() (map[string]interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if time.Since(c.cachedAt) > c.ttl {
		return nil, false
	}
	return c.stats, true
}

// set stores stats in the cache.
func (c *pgCache) set(stats map[string]interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.stats = stats
	c.cachedAt = time.Now()
}

// Collector implements metrics.Collector for PostgreSQL metrics.
type Collector struct {
	config   config.DatabaseConfig
	hostname string
	logger   *slog.Logger
	db       *sql.DB
	cache    *pgCache

	// Distribution-aware socket paths
	socketPaths    []string
	detectedSocket string
	isWindows      bool // True if running on Windows (use TCP instead of socket)
}

// CollectorOption configures the PostgreSQL collector.
type CollectorOption func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) CollectorOption {
	return func(c *Collector) {
		c.logger = logger
	}
}

// NewCollector creates a new PostgreSQL collector.
func NewCollector(cfg config.DatabaseConfig, hostname string, opts ...CollectorOption) *Collector {
	collector := &Collector{
		config:   cfg,
		hostname: hostname,
		logger:   slog.Default().With("component", "postgresql_collector"),
		cache:    newPGCache(),
		socketPaths: []string{
			// Most distributions
			"/var/run/postgresql",
			// Alpine/some containers
			"/run/postgresql",
			// Fallback
			"/tmp",
		},
	}

	for _, opt := range opts {
		opt(collector)
	}

	// Auto-detect if PostgreSQL is running
	if collector.detectPostgreSQL() {
		collector.logger.Info("PostgreSQL process detected, enabling monitoring")
		collector.connect()
	}

	return collector
}

// detectPostgreSQL is implemented in postgresql_unix.go and postgresql_windows.go
// based on the target operating system.

// connect establishes connection to PostgreSQL.
func (c *Collector) connect() error {
	connStr := c.buildConnStr()

	// Log connection attempt (mask password for security)
	c.logger.Info("attempting PostgreSQL connection", "using_socket", c.config.PostgreSQLSocket != "" && c.config.PostgreSQLSocket != "auto", "host", c.config.PostgreSQLHost)

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		c.logger.Warn("failed to open PostgreSQL connection", "error", err)
		return err
	}

	// Configure connection pool
	db.SetMaxOpenConns(3) // Conservative for monitoring
	db.SetMaxIdleConns(1) // Keep one idle connection
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		c.logger.Warn("failed to ping PostgreSQL", "error", err)
		return err
	}

	c.db = db
	c.logger.Info("PostgreSQL connection established successfully")
	return nil
}

// buildConnStr constructs the PostgreSQL connection string.
func (c *Collector) buildConnStr() string {
	database := c.config.PostgreSQLDatabase
	if database == "" {
		database = "postgres"
	}

	// Default to TCP connection (simpler, works everywhere, no pg_hba.conf changes needed)
	// Only use socket if user explicitly configured postgresql_socket path
	useSocket := c.config.PostgreSQLSocket != "" && c.config.PostgreSQLSocket != "auto" && !c.isWindows

	if c.config.PostgreSQLUser != "" {
		// Use credentials if provided
		if useSocket {
			return fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
				c.config.PostgreSQLSocket, c.config.PostgreSQLUser, c.config.PostgreSQLPassword, database)
		} else {
			// Default: TCP connection to localhost:5432
			// Parse host:port if provided, otherwise default to localhost:5432
			host := c.config.PostgreSQLHost
			port := "5432"
			if host == "" {
				host = "localhost"
			} else {
				// Split host:port if provided
				parts := strings.SplitN(host, ":", 2)
				if len(parts) == 2 {
					host = parts[0]
					port = parts[1]
				}
			}
			return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				host, port, c.config.PostgreSQLUser, c.config.PostgreSQLPassword, database)
		}
	} else {
		// Try connection without credentials (usually won't work)
		if useSocket {
			return fmt.Sprintf("host=%s dbname=%s sslmode=disable", c.config.PostgreSQLSocket, database)
		} else {
			host := c.config.PostgreSQLHost
			port := "5432"
			if host == "" {
				host = "localhost"
			} else {
				// Split host:port if provided
				parts := strings.SplitN(host, ":", 2)
				if len(parts) == 2 {
					host = parts[0]
					port = parts[1]
				}
			}
			return fmt.Sprintf("host=%s port=%s dbname=%s sslmode=disable", host, port, database)
		}
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "postgresql"
}

// Enabled returns whether the collector is enabled.
func (c *Collector) Enabled() bool {
	if c.db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return c.db.PingContext(ctx) == nil
}

// Collect gathers PostgreSQL metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	var collected []metrics.Metric
	timestamp := time.Now()

	// Basic health check - is PostgreSQL running?
	isRunning := c.checkProcess()
	collected = append(collected, metrics.Metric{
		Name:      "postgresql_up",
		Value:     boolToFloat(isRunning),
		Timestamp: timestamp,
		Labels: map[string]string{
			"host": c.hostname,
		},
	})

	if !isRunning {
		return collected, nil
	}

	// If we have a database connection, collect detailed metrics
	if c.db != nil {
		// Connection metrics
		connections, err := c.getConnectionStats(ctx)
		if err != nil {
			c.logger.Warn("failed to get connection stats", "error", err)
			// Try to reconnect
			c.connect()
		} else {
			collected = append(collected, metrics.Metric{
				Name:      "postgresql_connections_active",
				Value:     connections["active"],
				Timestamp: timestamp,
				Labels: map[string]string{
					"host": c.hostname,
				},
			})

			collected = append(collected, metrics.Metric{
				Name:      "postgresql_connections_idle",
				Value:     connections["idle"],
				Timestamp: timestamp,
				Labels: map[string]string{
					"host": c.hostname,
				},
			})

			collected = append(collected, metrics.Metric{
				Name:      "postgresql_connections_idle_in_transaction",
				Value:     connections["idle_in_transaction"],
				Timestamp: timestamp,
				Labels: map[string]string{
					"host": c.hostname,
				},
			})
		}

		// Database stats
		dbStats, err := c.getDatabaseStats(ctx)
		if err == nil {
			// Transaction metrics
			if val, ok := dbStats["xact_commit"]; ok {
				collected = append(collected, metrics.Metric{
					Name:      "postgresql_transactions_committed",
					Value:     val,
					Timestamp: timestamp,
					Labels: map[string]string{
						"host": c.hostname,
					},
				})
			}

			if val, ok := dbStats["xact_rollback"]; ok {
				collected = append(collected, metrics.Metric{
					Name:      "postgresql_transactions_rollback",
					Value:     val,
					Timestamp: timestamp,
					Labels: map[string]string{
						"host": c.hostname,
					},
				})
			}

			// Buffer cache metrics
			if val, ok := dbStats["blks_hit"]; ok {
				collected = append(collected, metrics.Metric{
					Name:      "postgresql_blocks_hit",
					Value:     val,
					Timestamp: timestamp,
					Labels: map[string]string{
						"host": c.hostname,
					},
				})
			}

			if val, ok := dbStats["blks_read"]; ok {
				collected = append(collected, metrics.Metric{
					Name:      "postgresql_blocks_read",
					Value:     val,
					Timestamp: timestamp,
					Labels: map[string]string{
						"host": c.hostname,
					},
				})
			}

			// Calculate buffer hit ratio
			if hits, ok1 := dbStats["blks_hit"]; ok1 {
				if reads, ok2 := dbStats["blks_read"]; ok2 {
					total := hits + reads
					if total > 0 {
						hitRatio := (hits / total) * 100
						collected = append(collected, metrics.Metric{
							Name:      "postgresql_buffer_hit_ratio",
							Value:     hitRatio,
							Timestamp: timestamp,
							Labels: map[string]string{
								"host": c.hostname,
							},
						})
					}
				}
			}

			// Dead tuples
			if val, ok := dbStats["n_dead_tup"]; ok {
				collected = append(collected, metrics.Metric{
					Name:      "postgresql_dead_tuples",
					Value:     val,
					Timestamp: timestamp,
					Labels: map[string]string{
						"host": c.hostname,
					},
				})
			}
		}

		// Lock metrics
		locks, err := c.getLockCount(ctx)
		if err == nil {
			collected = append(collected, metrics.Metric{
				Name:      "postgresql_locks_count",
				Value:     locks,
				Timestamp: timestamp,
				Labels: map[string]string{
					"host": c.hostname,
				},
			})
		}

		// Replication lag (if replica)
		lag, err := c.getReplicationLag(ctx)
		if err == nil && lag >= 0 {
			collected = append(collected, metrics.Metric{
				Name:      "postgresql_replication_lag_seconds",
				Value:     lag,
				Timestamp: timestamp,
				Labels: map[string]string{
					"host": c.hostname,
				},
			})
		}

		// pg_stat_statements metrics (if available)
		slowQueries, err := c.getSlowQueryCount(ctx)
		if err == nil {
			collected = append(collected, metrics.Metric{
				Name:      "postgresql_slow_queries_count",
				Value:     slowQueries,
				Timestamp: timestamp,
				Labels: map[string]string{
					"host": c.hostname,
				},
			})
		}

	} else {
		// No connection, just report that PostgreSQL is running
		collected = append(collected, metrics.Metric{
			Name:      "postgresql_connection_failed",
			Value:     1,
			Timestamp: timestamp,
			Labels: map[string]string{
				"host": c.hostname,
			},
		})
	}

	return collected, nil
}

// getConnectionStats gets connection statistics.
func (c *Collector) getConnectionStats(ctx context.Context) (map[string]float64, error) {
	stats := make(map[string]float64)

	query := `
		SELECT state, COUNT(*) 
		FROM pg_stat_activity 
		WHERE pid != pg_backend_pid()
		GROUP BY state`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var state sql.NullString
	var count int
	for rows.Next() {
		if err := rows.Scan(&state, &count); err != nil {
			continue
		}

		if state.Valid {
			switch state.String {
			case "active":
				stats["active"] = float64(count)
			case "idle":
				stats["idle"] = float64(count)
			case "idle in transaction":
				stats["idle_in_transaction"] = float64(count)
			}
		}
	}

	// Set defaults for missing states
	if _, ok := stats["active"]; !ok {
		stats["active"] = 0
	}
	if _, ok := stats["idle"]; !ok {
		stats["idle"] = 0
	}
	if _, ok := stats["idle_in_transaction"]; !ok {
		stats["idle_in_transaction"] = 0
	}

	return stats, nil
}

// getDatabaseStats gets database-level statistics.
func (c *Collector) getDatabaseStats(ctx context.Context) (map[string]float64, error) {
	stats := make(map[string]float64)

	query := `
		SELECT
			xact_commit,
			xact_rollback,
			blks_hit,
			blks_read,
			tup_returned,
			tup_fetched,
			tup_inserted,
			tup_updated,
			tup_deleted
		FROM pg_stat_database
		WHERE datname = current_database()`

	var xactCommit, xactRollback, blksHit, blksRead sql.NullInt64
	var tupReturned, tupFetched, tupInserted, tupUpdated, tupDeleted sql.NullInt64

	err := c.db.QueryRowContext(ctx, query).Scan(
		&xactCommit, &xactRollback, &blksHit, &blksRead,
		&tupReturned, &tupFetched, &tupInserted, &tupUpdated, &tupDeleted,
	)

	if err != nil {
		return nil, err
	}

	// n_live_tup and n_dead_tup are per-table stats (pg_stat_user_tables), not per-database
	deadTupQuery := `SELECT COALESCE(SUM(n_dead_tup), 0) FROM pg_stat_user_tables`
	var nDeadTup sql.NullInt64
	if err := c.db.QueryRowContext(ctx, deadTupQuery).Scan(&nDeadTup); err != nil {
		c.logger.Debug("failed to query dead tuple count", "error", err)
	}

	if xactCommit.Valid {
		stats["xact_commit"] = float64(xactCommit.Int64)
	}
	if xactRollback.Valid {
		stats["xact_rollback"] = float64(xactRollback.Int64)
	}
	if blksHit.Valid {
		stats["blks_hit"] = float64(blksHit.Int64)
	}
	if blksRead.Valid {
		stats["blks_read"] = float64(blksRead.Int64)
	}
	if tupReturned.Valid {
		stats["tup_returned"] = float64(tupReturned.Int64)
	}
	if tupFetched.Valid {
		stats["tup_fetched"] = float64(tupFetched.Int64)
	}
	if nDeadTup.Valid {
		stats["n_dead_tup"] = float64(nDeadTup.Int64)
	}

	return stats, nil
}

// getLockCount gets the current number of locks.
func (c *Collector) getLockCount(ctx context.Context) (float64, error) {
	var count int
	err := c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pg_locks").Scan(&count)
	if err != nil {
		return 0, err
	}
	return float64(count), nil
}

// getReplicationLag checks replication lag if this is a replica.
func (c *Collector) getReplicationLag(ctx context.Context) (float64, error) {
	var isInRecovery bool
	err := c.db.QueryRowContext(ctx, "SELECT pg_is_in_recovery()").Scan(&isInRecovery)
	if err != nil || !isInRecovery {
		// Not a replica
		return -1, fmt.Errorf("not a replica")
	}

	// Calculate replication lag
	var lag sql.NullFloat64
	err = c.db.QueryRowContext(ctx, `
		SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))
	`).Scan(&lag)

	if err != nil {
		return -1, err
	}

	if lag.Valid {
		return lag.Float64, nil
	}

	return -1, nil
}

// getSlowQueryCount gets count of slow queries from pg_stat_statements if available.
func (c *Collector) getSlowQueryCount(ctx context.Context) (float64, error) {
	// Check if pg_stat_statements extension is available
	var exists bool
	err := c.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
		)
	`).Scan(&exists)

	if err != nil || !exists {
		return 0, fmt.Errorf("pg_stat_statements not available")
	}

	// Count queries with mean time > 1000ms (1 second)
	var count int
	err = c.db.QueryRowContext(ctx, `
		SELECT COUNT(*) 
		FROM pg_stat_statements 
		WHERE mean_exec_time > 1000
	`).Scan(&count)

	if err != nil {
		// Try older column name for backwards compatibility
		err = c.db.QueryRowContext(ctx, `
			SELECT COUNT(*) 
			FROM pg_stat_statements 
			WHERE mean_time > 1000
		`).Scan(&count)

		if err != nil {
			return 0, err
		}
	}

	return float64(count), nil
}

// checkSocket checks if PostgreSQL socket directory exists.
func (c *Collector) checkSocket() bool {
	// Only check sockets on Unix-like systems
	if runtime.GOOS == "windows" {
		return false
	}

	// Check each known socket path
	for _, path := range c.socketPaths {
		// PostgreSQL uses directories for sockets, check if dir exists and has .s.PGSQL files
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			// Check for PostgreSQL socket files in the directory
			entries, err := os.ReadDir(path)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() && (entry.Name() == ".s.PGSQL.5432" || entry.Name() == ".s.PGSQL.5433") {
						c.detectedSocket = path
						return true
					}
				}
			}
		}
	}
	return false
}

// checkProcess is implemented in postgresql_unix.go and postgresql_windows.go
// based on the target operating system.

// HealthCheck performs a health check.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// First check if PostgreSQL is even installed/running
	hasSocket := c.checkSocket()
	hasProcess := c.checkProcess()

	if !hasSocket && !hasProcess {
		// PostgreSQL is not installed or running - this is not an error, just log info
		c.logger.Info("No PostgreSQL service detected")
		return nil
	}

	// PostgreSQL appears to be installed, now check if we can connect
	if c.db != nil {
		// Try a simple query
		var result int
		err := c.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
		if err != nil {
			return fmt.Errorf("PostgreSQL health check query failed: %w", err)
		}
	} else if hasSocket || hasProcess {
		// PostgreSQL is running but we're not connected - this might be intentional
		c.logger.Info("PostgreSQL detected but not configured for monitoring")
	}

	return nil
}

// Close cleans up the collector.
func (c *Collector) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Helper functions

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
