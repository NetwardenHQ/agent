// Package mysql provides MySQL/MariaDB metrics collection for the Netwarden agent.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql" // MySQL driver; also registers "mysql"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// mysqlCache provides caching for MySQL stats to reduce query load.
type mysqlCache struct {
	stats    map[string]float64
	cachedAt time.Time
	ttl      time.Duration
	mutex    sync.RWMutex
}

// newMySQLCache creates a new MySQL cache with 30-second TTL.
func newMySQLCache() *mysqlCache {
	return &mysqlCache{
		ttl:   30 * time.Second,
		stats: make(map[string]float64),
	}
}

// get retrieves cached stats if they're still valid.
func (c *mysqlCache) get() (map[string]float64, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if time.Since(c.cachedAt) > c.ttl {
		return nil, false
	}
	return c.stats, true
}

// set stores stats in the cache.
func (c *mysqlCache) set(stats map[string]float64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.stats = stats
	c.cachedAt = time.Now()
}

// Collector implements metrics.Collector for MySQL metrics.
type Collector struct {
	config   config.DatabaseConfig
	hostname string
	logger   *slog.Logger
	db       *sql.DB
	cache    *mysqlCache

	// Distribution-aware socket paths
	socketPaths    []string
	detectedSocket string
}

// CollectorOption configures the MySQL collector.
type CollectorOption func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) CollectorOption {
	return func(c *Collector) {
		c.logger = logger
	}
}

// NewCollector creates a new MySQL collector.
func NewCollector(cfg config.DatabaseConfig, hostname string, opts ...CollectorOption) *Collector {
	collector := &Collector{
		config:   cfg,
		hostname: hostname,
		logger:   slog.Default().With("component", "mysql_collector"),
		cache:    newMySQLCache(),
		socketPaths: []string{
			// Ubuntu/Debian
			"/var/run/mysqld/mysqld.sock",
			// RHEL/CentOS/Fedora
			"/var/lib/mysql/mysql.sock",
			// SUSE (newer)
			"/var/run/mysql/mysql.sock",
			// Alpine
			"/run/mysqld/mysqld.sock",
			// Arch
			"/var/run/mysqld/mysqld.sock",
			// Default fallback
			"/tmp/mysql.sock",
		},
	}

	for _, opt := range opts {
		opt(collector)
	}

	// Auto-detect if MySQL is running
	if collector.detectMySQL() {
		collector.logger.Info("MySQL/MariaDB process detected, enabling monitoring")
		collector.connect()
	}

	return collector
}

// detectMySQL is implemented in mysql_unix.go and mysql_windows.go
// based on the target operating system.

// connect establishes connection to MySQL.
func (c *Collector) connect() error {
	dsn := c.buildDSN()

	// Open database connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		c.logger.Warn("failed to open MySQL connection", "error", err)
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
		c.logger.Warn("failed to ping MySQL", "error", err)
		return err
	}

	c.db = db
	c.logger.Info("MySQL connection established successfully")
	return nil
}

// buildDSN constructs the MySQL data source name.
//
// The driver's own FormatDSN does the escaping, so credentials containing
// "@", "/" or ")" cannot break or redirect the DSN. A remote TCP host gets
// tls=preferred (TLS when the server offers it); the local socket and
// loopback stay plain.
func (c *Collector) buildDSN() string {
	// TCP unless mysql_socket names a socket explicitly.
	useSocket := c.config.MySQLSocket != "" && c.config.MySQLSocket != "auto"

	cfg := mysql.NewConfig()
	// Credentials are sent only as a pair; otherwise the connection is
	// attempted anonymously.
	if c.config.MySQLUser != "" && c.config.MySQLPassword != "" {
		cfg.User = c.config.MySQLUser
		cfg.Passwd = c.config.MySQLPassword
	}
	if useSocket {
		cfg.Net, cfg.Addr = "unix", c.config.MySQLSocket
	} else {
		cfg.Net, cfg.Addr = "tcp", c.config.MySQLHost
		if cfg.Addr == "" {
			cfg.Addr = "localhost:3306"
		}
		if !isLoopbackHost(cfg.Addr) {
			cfg.TLSConfig = "preferred"
		}
	}
	return cfg.FormatDSN()
}

// isLoopbackHost reports whether a host[:port] is this machine.
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
	return "mysql"
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

// Collect gathers MySQL metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	var collected []metrics.Metric
	timestamp := time.Now()

	// Basic health check - is MySQL running?
	isRunning := c.checkProcess()
	collected = append(collected, metrics.Metric{
		Name:      "mysql_up",
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
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := c.db.PingContext(pingCtx); err == nil {
			stats, err := c.collectStats(ctx)
			if err != nil {
				c.logger.Warn("failed to collect MySQL stats", "error", err)
				// Try to reconnect
				c.db.Close()
				if reconnectErr := c.connect(); reconnectErr != nil {
					c.logger.Error("failed to reconnect to MySQL", "error", reconnectErr)
				}
			} else {
				// Connection metrics
				if val, ok := stats["Threads_connected"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_connections_current",
						Value:     val,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}

				if val, ok := stats["Max_used_connections"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_connections_max_used",
						Value:     val,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}

				// Query metrics
				if val, ok := stats["Queries"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_queries_total",
						Value:     val,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}

				if val, ok := stats["Slow_queries"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_slow_queries_total",
						Value:     val,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}

				// InnoDB buffer pool metrics
				if val, ok := stats["Innodb_buffer_pool_read_requests"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_innodb_buffer_pool_read_requests",
						Value:     val,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}

				if val, ok := stats["Innodb_buffer_pool_reads"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_innodb_buffer_pool_reads",
						Value:     val,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}

				// Calculate buffer pool hit ratio
				if requests, ok1 := stats["Innodb_buffer_pool_read_requests"]; ok1 {
					if reads, ok2 := stats["Innodb_buffer_pool_reads"]; ok2 {
						if requests > 0 {
							hitRatio := (1 - (reads / requests)) * 100
							collected = append(collected, metrics.Metric{
								Name:      "mysql_buffer_pool_hit_ratio",
								Value:     hitRatio,
								Timestamp: timestamp,
								Labels: map[string]string{
									"host": c.hostname,
								},
							})
						}
					}
				}

				// Table locks
				if val, ok := stats["Table_locks_waited"]; ok {
					collected = append(collected, metrics.Metric{
						Name:      "mysql_table_locks_waited",
						Value:     val,
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
						Name:      "mysql_replication_lag_seconds",
						Value:     lag,
						Timestamp: timestamp,
						Labels: map[string]string{
							"host": c.hostname,
						},
					})
				}
			}
		}
	} else {
		// No connection: report only that MySQL is running.
		collected = append(collected, metrics.Metric{
			Name:      "mysql_connection_failed",
			Value:     1,
			Timestamp: timestamp,
			Labels: map[string]string{
				"host": c.hostname,
			},
		})
	}

	return collected, nil
}

// collectStats gathers MySQL statistics from SHOW STATUS.
func (c *Collector) collectStats(ctx context.Context) (map[string]float64, error) {
	// Check cache first
	if stats, ok := c.cache.get(); ok {
		return stats, nil
	}

	// Check database connection
	if c.db == nil {
		return nil, fmt.Errorf("no database connection available")
	}

	stats := make(map[string]float64)

	rows, err := c.db.QueryContext(ctx, "SHOW GLOBAL STATUS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var name string
	var value string
	for rows.Next() {
		if err := rows.Scan(&name, &value); err != nil {
			continue
		}

		// Convert to float where possible
		if fval, err := parseFloat(value); err == nil {
			stats[name] = fval
		}
	}

	// Cache the results
	c.cache.set(stats)

	return stats, nil
}

// getReplicationLag checks replication lag if this is a replica.
func (c *Collector) getReplicationLag(ctx context.Context) (float64, error) {
	// Get database connection from pool
	if c.db == nil {
		return -1, fmt.Errorf("no database connection available")
	}

	var lag sql.NullFloat64
	err := c.db.QueryRowContext(ctx,
		"SELECT COALESCE(Seconds_Behind_Master, -1) FROM information_schema.processlist WHERE command = 'Binlog Dump'").Scan(&lag)

	if err != nil {
		// Not a replica or no replication
		return -1, err
	}

	if lag.Valid {
		return lag.Float64, nil
	}

	return -1, nil
}

// checkSocket checks if MySQL socket file exists.
func (c *Collector) checkSocket() bool {
	// Only check sockets on Unix-like systems
	if runtime.GOOS == "windows" {
		return false
	}

	// Check each known socket path
	for _, path := range c.socketPaths {
		if _, err := os.Stat(path); err == nil {
			c.detectedSocket = path
			return true
		}
	}
	return false
}

// checkProcess is implemented in mysql_unix.go and mysql_windows.go
// based on the target operating system.

// HealthCheck performs a health check.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// First check if MySQL is even installed/running
	hasSocket := c.checkSocket()
	hasProcess := c.checkProcess()

	if !hasSocket && !hasProcess {
		// MySQL is not installed or not running, which is not an error.
		c.logger.Info("No MySQL service detected")
		return nil
	}

	// MySQL appears to be installed; check whether it accepts a connection.
	if c.db != nil {
		// Try a simple query to verify database connectivity
		var result int
		err := c.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
		if err != nil {
			return fmt.Errorf("MySQL health check query failed: %w", err)
		}
	} else if hasSocket || hasProcess {
		// MySQL is running but we're not connected - this might be intentional
		c.logger.Info("MySQL detected but not configured for monitoring")
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

func parseFloat(s string) (float64, error) {
	// Handle ON/OFF values
	switch strings.ToUpper(s) {
	case "ON", "YES", "TRUE":
		return 1, nil
	case "OFF", "NO", "FALSE":
		return 0, nil
	}

	// Try to parse as number
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}
