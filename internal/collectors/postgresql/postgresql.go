// Package postgresql provides PostgreSQL metrics collection for the Netwarden agent.
package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Collector implements metrics.Collector for PostgreSQL metrics.
type Collector struct {
	config   config.DatabaseConfig
	hostname string
	logger   *slog.Logger
	db       *sql.DB

	// active is set once, at construction, when PostgreSQL is enabled in the
	// config or a server process was found. It does not depend on the
	// connection: a server the agent cannot reach still reports
	// postgresql_up and postgresql_connection_failed.
	active bool
	// processRunning replaces checkProcess in tests.
	processRunning func() bool
	// connFailing remembers that the last connection attempt failed, so the
	// failure is logged once rather than every cycle.
	connFailing bool

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

	// Monitor when enabled in the config or when a local server is running.
	if collector.detectPostgreSQL() {
		collector.logger.Info("PostgreSQL process detected, enabling monitoring")
		collector.active = true
	} else if cfg.EnablePostgreSQL {
		collector.active = true
	}
	if collector.active {
		_ = collector.connect()
	}

	return collector
}

// detectPostgreSQL is implemented in postgresql_unix.go and postgresql_windows.go
// based on the target operating system.

// connect establishes connection to PostgreSQL.
func (c *Collector) connect() error {
	connStr := c.buildConnStr()

	// Log connection attempt (mask password for security)
	c.logger.Debug("attempting PostgreSQL connection", "using_socket", c.config.PostgreSQLSocket != "" && c.config.PostgreSQLSocket != "auto", "host", c.config.PostgreSQLHost)

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
//
// Every value is quoted (pqQuote), so a password with a space, quote or
// "key=value" text in it stays one value instead of rewriting the options.
// sslmode is disable for a unix socket or a loopback host and prefer (TLS
// when the server offers it) for anything else; lib/pq supports prefer.
func (c *Collector) buildConnStr() string {
	database := c.config.PostgreSQLDatabase
	if database == "" {
		database = "postgres"
	}

	// TCP unless postgresql_socket names a socket explicitly; TCP needs no
	// pg_hba.conf changes on a default install.
	useSocket := c.config.PostgreSQLSocket != "" && c.config.PostgreSQLSocket != "auto" && !c.isWindows

	var kv []string
	add := func(key, value string) { kv = append(kv, key+"="+pqQuote(value)) }

	if useSocket {
		add("host", c.config.PostgreSQLSocket)
	} else {
		// postgresql_host defaults to localhost:5432 and may carry a port ("db:6543", "[::1]:6543").
		host, port := c.config.PostgreSQLHost, "5432"
		if host == "" {
			host = "localhost"
		} else if h, p, err := net.SplitHostPort(host); err == nil {
			host, port = h, p
		}
		add("host", host)
		add("port", port)
	}
	// Without credentials the connection usually fails, but it is tried.
	if c.config.PostgreSQLUser != "" {
		add("user", c.config.PostgreSQLUser)
		add("password", c.config.PostgreSQLPassword)
	}
	add("dbname", database)

	sslmode := "prefer"
	if useSocket || isLoopbackHost(c.config.PostgreSQLHost) {
		sslmode = "disable"
	}
	add("sslmode", sslmode)
	return strings.Join(kv, " ")
}

// pqQuote quotes a libpq key/value connection-string value: single quotes,
// with backslash and single quote backslash-escaped.
func pqQuote(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(v) + "'"
}

// isLoopbackHost reports whether a configured host (optionally host:port) is
// this machine. Empty means the localhost default.
func isLoopbackHost(hostPort string) bool {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "postgresql"
}

// Enabled reports whether PostgreSQL is monitored on this host: configured,
// or detected at startup. Reachability is reported by Collect, not here; a
// collector that disabled itself on a failed ping could never say the
// database is down.
func (c *Collector) Enabled() bool {
	return c.active
}

// ensureConnected returns a live connection, reconnecting when the previous
// one was lost or never made.
func (c *Collector) ensureConnected(ctx context.Context) error {
	if c.db != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := c.db.PingContext(pingCtx)
		cancel()
		if err == nil {
			return nil
		}
		c.db.Close()
		c.db = nil
	}
	return c.connect()
}

// connectionUsage reads the connection limit and how many client backends
// count against it. Background workers and replication senders do not, so
// they are left out.
func (c *Collector) connectionUsage(ctx context.Context) (used, limit float64, err error) {
	var u, l sql.NullInt64
	err = c.db.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'),
		       current_setting('max_connections')::int`).Scan(&u, &l)
	if err != nil {
		return 0, 0, err
	}
	if !l.Valid || l.Int64 <= 0 {
		return 0, 0, fmt.Errorf("max_connections not set")
	}
	return float64(u.Int64), float64(l.Int64), nil
}

// gauge builds one host-labeled PostgreSQL gauge.
func (c *Collector) gauge(name string, value float64, ts time.Time) metrics.Metric {
	return metrics.Metric{
		Name:      name,
		Value:     value,
		Timestamp: ts,
		Labels:    map[string]string{"host": c.hostname},
	}
}

// Collect gathers PostgreSQL metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	var collected []metrics.Metric
	timestamp := time.Now()

	// Basic health check - is PostgreSQL running?
	running := c.checkProcess
	if c.processRunning != nil {
		running = c.processRunning
	}
	isRunning := running()
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

	if err := c.ensureConnected(ctx); err != nil {
		if !c.connFailing {
			c.logger.Warn("PostgreSQL is running but the agent cannot connect; reporting postgresql_connection_failed", "error", err)
		}
		c.connFailing = true
		collected = append(collected, c.gauge("postgresql_connection_failed", 1, timestamp))
		return collected, nil
	}
	if c.connFailing {
		c.logger.Info("PostgreSQL connection restored")
	}
	c.connFailing = false
	collected = append(collected, c.gauge("postgresql_connection_failed", 0, timestamp))

	// The limit, so connections can be judged as a share of it. A full
	// server refuses new clients with "too many clients already".
	if used, limit, err := c.connectionUsage(ctx); err == nil {
		collected = append(collected,
			c.gauge("postgresql_max_connections", limit, timestamp),
			c.gauge("postgresql_connections_used_percent", used/limit*100, timestamp))
	} else {
		c.logger.Debug("could not read connection usage", "error", err)
	}

	// Connection metrics
	connections, err := c.getConnectionStats(ctx)
	if err != nil {
		c.logger.Warn("failed to get connection stats", "error", err)
		// Drop the connection; the next cycle reconnects.
		c.db.Close()
		c.db = nil
		return collected, nil
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
		// PostgreSQL is not installed or not running, which is not an error.
		c.logger.Info("No PostgreSQL service detected")
		return nil
	}

	// PostgreSQL appears to be installed; check whether it accepts a connection.
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
