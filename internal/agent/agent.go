// Copyright 2024-2026 Netwarden
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package agent coordinates metric collection, filtering and transmission.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/cache"
	"github.com/NetwardenHQ/agent/internal/collectors/cis"
	"github.com/NetwardenHQ/agent/internal/collectors/container"
	"github.com/NetwardenHQ/agent/internal/collectors/cpu"
	"github.com/NetwardenHQ/agent/internal/collectors/disk"
	"github.com/NetwardenHQ/agent/internal/collectors/k8s"
	"github.com/NetwardenHQ/agent/internal/collectors/memory"
	"github.com/NetwardenHQ/agent/internal/collectors/mysql"
	"github.com/NetwardenHQ/agent/internal/collectors/network"
	"github.com/NetwardenHQ/agent/internal/collectors/opnsense"
	"github.com/NetwardenHQ/agent/internal/collectors/postgresql"
	"github.com/NetwardenHQ/agent/internal/collectors/process"
	"github.com/NetwardenHQ/agent/internal/collectors/system"
	"github.com/NetwardenHQ/agent/internal/config"
	sharedhttp "github.com/NetwardenHQ/agent/internal/http"
	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/registry"
	"github.com/NetwardenHQ/agent/internal/selfupdate"
	"github.com/NetwardenHQ/agent/internal/spool"
)

const (
	// defaultReportingInterval applies until the server says otherwise.
	defaultReportingInterval = 60 * time.Second

	// minReportingInterval and maxReportingInterval bound what the server may
	// ask for; anything outside is treated as a bad response.
	minReportingInterval = 10 * time.Second
	maxReportingInterval = 1 * time.Hour

	// batchSize is the most metrics sent in one request.
	batchSize = 500

	// startupJitterMax spreads a fleet's first requests after a mass restart.
	startupJitterMax = 20 * time.Second

	// updateCheckInterval is how often the OS package manager is asked about
	// pending updates. It shells out, so it runs off the collection path.
	updateCheckInterval = 6 * time.Hour
)

// Agent is the Netwarden agent: a set of collectors, a delta filter and a
// transmitter, driven by one collection loop.
type Agent struct {
	config   *config.Config
	logger   *slog.Logger
	registry metrics.Registry
	hostname string
	version  string

	transmitter  MetricTransmitter
	deltaTracker *metrics.DeltaTracker
	httpClient   *http.Client // for the remote-config fetch

	// cisCollector is held by concrete type (not through the registry) so the
	// remote-config poll can push a new CIS profile into it. nil when CIS is
	// disabled in netwarden.conf.
	cisCollector *cis.Collector

	// k8sCollector is likewise held concretely so the config poll can push the
	// namespace scope the operator configured in the UI.
	k8sCollector *k8s.Collector

	// opnsenseCollector is held concretely so device_identity can read the
	// interface roles and capabilities from it.
	opnsenseCollector *opnsense.Collector

	// spool forwards local producers' event and exposure files. It is nil when
	// no spool directory is configured, and its methods are no-ops on nil.
	spool *spool.Reader

	// identityEnabled turns on the per-cycle device_identity snapshot and the
	// spool. False only for hand-built agents in tests.
	identityEnabled bool
	state           *stateFile
	lastIdentityErr string

	// undelivered holds the snapshots of a post that failed. They ride with
	// the next cycle's post; see mergeSnapshots. Only the report loop
	// touches it.
	undelivered []metrics.Snapshot

	// backlog keeps the metrics of posts that failed until they can be
	// delivered. Nil keeps nothing.
	backlog *backlog

	// The settings revision last seen in a report reply, whether the config
	// has been fetched since start, and when it was last asked for. See
	// configChanged. Only the report loop touches them.
	seenConfigRev   string
	configFetched   bool
	lastConfigFetch time.Time

	// updater is closed on shutdown so a scheduled update is abandoned
	// rather than started mid-shutdown. Nil when self-update is not wired.
	updater *selfupdate.Updater

	stopChan chan struct{}
	stopOnce sync.Once

	// urgent asks the report loop for a cycle now (a collector saw something
	// that should not wait for the interval). Buffered by one: a request
	// made while one is pending is the same request.
	urgent chan struct{}

	cacheCleanupStop chan struct{}

	mu                  sync.Mutex
	reportingInterval   time.Duration // set by the server; see FetchRemoteConfig
	consecutiveFailures int           // transmission failures since the last success
}

// MetricTransmitter sends one batch of metrics, plus any snapshots for the
// cycle, to the server.
type MetricTransmitter interface {
	// Send transmits one batch. snapshots may be nil; when non-nil it is
	// sent alongside the batch in the same request.
	Send(ctx context.Context, metrics []metrics.Metric, snapshots []metrics.Snapshot) error
	Close() error
}

// New creates an agent from a loaded configuration.
func New(cfg *config.Config, logger *slog.Logger, version string) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	hostname := cfg.Hostname
	if hostname != "" {
		logger.Info("using custom hostname from config", "hostname", hostname)
	} else {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			hostname = "unknown"
			logger.Warn("failed to get hostname", "error", err)
		}
	}

	transmitter, err := NewHTTPTransmitter(cfg, hostname, version, logger.With("component", "transmitter"))
	if err != nil {
		return nil, fmt.Errorf("failed to create transmitter: %w", err)
	}

	// Self-update. The trigger rides on the reply to the metrics POST, so
	// there is no second destination to allowlist and no inbound channel. A
	// local self_update_url outranks the server's URL, the digest comes from
	// the API rather than the download host, and the accepted signers are
	// local-only. Nothing is installed before its signature is verified
	// against them; see internal/selfupdate.
	var updater *selfupdate.Updater
	if httpTx, ok := transmitter.(*HTTPTransmitter); ok {
		updater = selfupdate.New(selfupdate.Config{
			Enabled:         cfg.SelfUpdate.Enabled,
			WindowStartHour: cfg.SelfUpdate.WindowStartHour,
			WindowEndHour:   cfg.SelfUpdate.WindowEndHour,
			CurrentVersion:  version,
			URLTemplate:     cfg.SelfUpdate.URLTemplate,
			Signers:         cfg.SelfUpdate.Signers,
			AttemptsFile:    selfupdate.AttemptsFile(),
		}, logger.With("component", "selfupdate"))
		httpTx.SetUpdateHintHandler(updater.HandleHint)
		httpTx.SetSelfUpdateState(updater.State)
	}

	a := &Agent{
		config:   cfg,
		logger:   logger,
		registry: registry.NewRegistry(logger.With("component", "registry")),
		hostname: hostname,
		version:  version,

		transmitter: transmitter,
		updater:     updater,
		deltaTracker: metrics.NewDeltaTracker(metrics.DeltaConfig{
			Threshold: 1.0,             // resend a gauge when it moves by 1%
			MaxAge:    5 * time.Minute, // ...or at least every 5 minutes
			Logger:    logger.With("component", "delta"),
		}),
		httpClient: sharedhttp.GetClient(),

		backlog:           newBacklog(),
		stopChan:          make(chan struct{}),
		urgent:            make(chan struct{}, 1),
		cacheCleanupStop:  cache.StartGlobalCleanup(5 * time.Minute),
		reportingInterval: defaultReportingInterval,
	}

	a.identityEnabled = true
	if cfg.SpoolDir != "" {
		opts := []spool.Option{spool.WithLogger(logger.With("component", "spool"))}
		if cfg.SpoolVolume != "" {
			// In a pod the agent is not root; the spool is its own, inside an
			// emptyDir no other container mounts.
			opts = append(opts, spool.WithOwnVolume(cfg.SpoolVolume))
		}
		a.spool = spool.New(cfg.SpoolDir, opts...)
		if cfg.SpoolVolume == "" && !spool.CanCreateDirs() {
			logger.Info("not running as root; spool directories are not created", "dir", cfg.SpoolDir)
		} else if err := a.spool.EnsureDirs(); err != nil {
			logger.Warn("could not create spool directories", "dir", cfg.SpoolDir, "error", err)
		}
	}
	a.state = newStateFile(cfg.SpoolDir, version, time.Now(), logger.With("component", "state"))
	a.state.Init(a.currentInterval())

	if err := a.registerCollectors(); err != nil {
		return nil, fmt.Errorf("failed to register collectors: %w", err)
	}

	logger.Info("Netwarden agent created",
		"hostname", hostname,
		"collectors", a.registry.ListCollectors())

	return a, nil
}

// registerCollectors registers every collector the configuration enables.
func (a *Agent) registerCollectors() error {
	collectorLogger := a.logger.With("component", "collector")
	register := func(what string, c metrics.Collector) error {
		if err := a.registry.Register(c); err != nil {
			return fmt.Errorf("failed to register %s collector: %w", what, err)
		}
		return nil
	}

	if a.config.Collectors.CPU {
		if err := register("CPU", cpu.NewCollector(a.hostname, cpu.WithLogger(collectorLogger.With("type", "cpu")))); err != nil {
			return err
		}
	}

	if a.config.Collectors.Memory {
		if err := register("memory", memory.NewCollector(a.hostname, memory.WithLogger(collectorLogger.With("type", "memory")))); err != nil {
			return err
		}
	}

	if a.config.Collectors.System {
		c := system.NewCollector(
			config.SystemConfig{Enabled: true, CollectUptime: true},
			a.hostname,
			system.WithLogger(collectorLogger.With("type", "system")),
		)
		if err := register("system", c); err != nil {
			return err
		}
	}

	if a.config.Collectors.Disk {
		if err := register("disk", disk.NewCollector(a.hostname, disk.WithLogger(collectorLogger.With("type", "disk")))); err != nil {
			return err
		}
	}

	if a.config.Collectors.Network {
		c := network.NewCollector(a.config.Network, a.hostname, network.WithLogger(collectorLogger.With("type", "network")))
		if err := register("network", c); err != nil {
			return err
		}
	}

	if a.config.Collectors.Container {
		c := container.NewCollector(a.config.Container, a.hostname, container.WithLogger(collectorLogger.With("type", "container")))
		if err := register("container", c); err != nil {
			return err
		}
	}

	// The Kubernetes collector is active only when the agent runs inside a
	// cluster (in-cluster ServiceAccount detected). On an ordinary host it
	// registers but reports Enabled() == false. Default on; disable with
	// enable_kubernetes: false.
	if a.config.Collectors.Kubernetes {
		// Capabilities mirror the RBAC the install manifest granted, so the
		// agent never starts a watcher it has no permission for (which would
		// retry forever, logging a 403 each time).
		c := k8s.NewCollector(
			a.hostname,
			k8s.WithLogger(collectorLogger.With("type", "kubernetes")),
			k8s.WithCapabilities(k8s.Capabilities{
				Jobs:         a.config.Collectors.K8sJobs,
				Availability: a.config.Collectors.K8sAvailability,
				Resources:    a.config.Collectors.K8sResources,
				CNPG:         a.config.Collectors.K8sCNPG,
				Ingress:      a.config.Collectors.K8sIngress,
				IngressLogs:  a.config.Collectors.K8sIngressLogs,
			}),
			k8s.WithIngressLogs(a.config.K8sIngressLogsNamespace),
			k8s.WithSpoolDir(a.config.SpoolDir),
			k8s.WithUrgent(a.requestReport),
		)
		if err := register("kubernetes", c); err != nil {
			return err
		}
		a.k8sCollector = c
		if !c.Enabled() {
			a.logger.Debug("kubernetes collector registered but inactive (not in-cluster)")
		}
	}

	// VM collector (Linux only; see collectors_linux.go).
	if err := a.registerVMCollector(collectorLogger); err != nil {
		return err
	}

	// Security-posture collectors (per-collector platform support; see
	// collectors_security.go). Each is individually disableable via
	// enable_security_* in the config file.
	a.registerSecurityCollectors(collectorLogger)

	// Database collectors are always registered. One that is neither enabled
	// in the config nor finds a local server reports Enabled() == false and
	// is skipped; it looks again periodically, so a database installed after
	// the agent is monitored without a restart.
	mysqlCollector := mysql.NewCollector(a.config.Database, a.hostname, mysql.WithLogger(collectorLogger.With("type", "mysql")))
	if err := a.registry.Register(mysqlCollector); err != nil {
		a.logger.Debug("MySQL collector not registered", "error", err)
	}

	postgresqlCollector := postgresql.NewCollector(a.config.Database, a.hostname, postgresql.WithLogger(collectorLogger.With("type", "postgresql")))
	if err := a.registry.Register(postgresqlCollector); err != nil {
		a.logger.Debug("PostgreSQL collector not registered", "error", err)
	}

	if a.config.Process.EnableProcessMonitoring {
		c := process.NewCollector(
			a.config.Process,
			a.hostname,
			a.config.APIKey,
			a.config.ServerURL,
			process.WithLogger(collectorLogger.With("type", "process")),
			process.WithUserAgent(a.userAgent()),
		)
		if err := a.registry.Register(c); err != nil {
			a.logger.Warn("failed to register process collector", "error", err)
		}
	}

	return nil
}

// userAgent is the User-Agent header for every request the agent makes.
func (a *Agent) userAgent() string {
	return "Netwarden-Agent/" + a.version
}

// remoteConfig is the /agent/config response body. The API wraps every
// response as {success, data}.
type remoteConfig struct {
	Success bool `json:"success"`
	Data    struct {
		ReportingInterval int    `json:"reporting_interval"`
		TenantID          string `json:"tenant_id"`
		PlanID            string `json:"plan_id"`

		// CISProfile is the benchmark profile the operator defined in the
		// UI. Absent or null means CIS evaluation stays off for this host.
		CISProfile *cis.Profile `json:"cis_profile"`

		// AcceptsGzip says the server reads gzip-compressed reports.
		AcceptsGzip bool `json:"accepts_gzip"`

		// K8sConfig carries the cluster scope configured in the UI. Absent
		// means no scoping: watch every namespace.
		K8sConfig *struct {
			ExcludedNamespaces  []string `json:"excluded_namespaces"`
			SustainedForSeconds int      `json:"sustained_for_seconds"`
			RolloutGraceSeconds int      `json:"rollout_grace_seconds"`
		} `json:"k8s_config"`
	} `json:"data"`
}

// FetchRemoteConfig retrieves the reporting interval and collector settings
// the server holds for this host, and applies them.
func (a *Agent) FetchRemoteConfig(ctx context.Context) error {
	a.lastConfigFetch = time.Now()
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, a.config.ServerURL+"/agent/config", nil)
	if err != nil {
		return fmt.Errorf("creating config request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)
	req.Header.Set("User-Agent", a.userAgent())

	resp, err := a.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("config fetch timed out after 10s")
		}
		return fmt.Errorf("fetching config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config fetch failed: status %d", resp.StatusCode)
	}

	var body remoteConfig
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decoding config: %w", err)
	}
	if !body.Success {
		return fmt.Errorf("API returned success=false")
	}

	if body.Data.AcceptsGzip {
		if tx, ok := a.transmitter.(interface{ AllowGzip() }); ok {
			tx.AllowGzip()
		}
	}

	// Apply the collector settings before validating the interval: a server
	// that returns a nonsensical interval should not also silently discard a
	// profile change the operator just made.
	if a.cisCollector != nil {
		a.cisCollector.SetProfile(body.Data.CISProfile)
	}
	if a.k8sCollector != nil {
		var excluded []string
		var sustained, rollout time.Duration
		if k := body.Data.K8sConfig; k != nil {
			excluded = k.ExcludedNamespaces
			sustained = time.Duration(k.SustainedForSeconds) * time.Second
			rollout = time.Duration(k.RolloutGraceSeconds) * time.Second
		}
		a.k8sCollector.SetExcludedNamespaces(excluded)
		// Zero means unset in the UI; the collector keeps its default.
		a.k8sCollector.SetThresholds(sustained, rollout)
	}

	interval := time.Duration(body.Data.ReportingInterval) * time.Second
	if interval < minReportingInterval || interval > maxReportingInterval {
		return fmt.Errorf("invalid reporting interval from server: %d seconds", body.Data.ReportingInterval)
	}

	a.mu.Lock()
	old := a.reportingInterval
	a.reportingInterval = interval
	a.mu.Unlock()
	a.configFetched = true

	if old != interval {
		a.logger.Info("reporting interval updated",
			"old_interval", old.String(),
			"new_interval", interval.String(),
			"plan_id", body.Data.PlanID)
	}
	return nil
}

// minConfigRefetchGap bounds how often a changed revision makes the agent
// fetch its config. Two servers can name different revisions for up to a
// minute after a change; without the bound each reply would cost a fetch.
const minConfigRefetchGap = 30 * time.Second

// configChanged reports whether the settings revision in the last report
// reply means the config should be fetched now.
//
// Every reply names the revision of the settings the server holds for this
// host. A change made in the UI changes it, and the agent applies the change
// within a cycle or two; the hourly refresh is the fallback for a server that
// names no revision. An agent whose startup fetch failed fetches as soon as
// the server answers a report.
func (a *Agent) configChanged(now time.Time) bool {
	tx, ok := a.transmitter.(interface{ ConfigRev() string })
	if !ok {
		return false
	}
	rev := tx.ConfigRev()
	if rev == "" || rev == a.seenConfigRev {
		return false
	}
	if a.seenConfigRev == "" && a.configFetched {
		// The config fetched at startup is this revision.
		a.seenConfigRev = rev
		return false
	}
	if now.Sub(a.lastConfigFetch) < minConfigRefetchGap {
		return false
	}
	a.seenConfigRev = rev
	return true
}

// currentInterval returns the reporting interval in effect.
func (a *Agent) currentInterval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reportingInterval
}

// testConnection performs a startup connectivity check against the server.
// It logs the result and never blocks startup.
func (a *Agent) testConnection(ctx context.Context) {
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, a.config.ServerURL+"/agent/config", nil)
	if err != nil {
		a.logger.Warn("failed to create connection test request", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)
	req.Header.Set("User-Agent", a.userAgent())

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Warn("server connection test failed",
			"server_url", a.config.ServerURL,
			"error", err,
			"hint", "check server_url, network connectivity, and TLS settings")
		return
	}
	resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		a.logger.Error("server reachable but authentication failed",
			"server_url", a.config.ServerURL,
			"hint", "check tenant_id and api_key in config")
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		a.logger.Info("connected to Netwarden server", "server_url", a.config.ServerURL)
	default:
		a.logger.Warn("server returned unexpected status",
			"server_url", a.config.ServerURL,
			"status", resp.StatusCode)
	}
}

// sleep waits for d or until ctx is done, reporting which.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run drives the collection loop until ctx is cancelled or Stop is called.
func (a *Agent) Run(ctx context.Context) error {
	a.testConnection(ctx)

	// Spread a fleet's first requests so a mass restart is not a stampede.
	if err := sleep(ctx, rand.N(startupJitterMax)); err != nil {
		return err
	}

	if err := a.FetchRemoteConfig(ctx); err != nil {
		a.logger.Error("failed to fetch remote config on startup; using default interval",
			"error", err,
			"hostname", a.hostname,
			"tenant_id", a.config.TenantID,
			"default_interval", a.currentInterval().String())
	}

	a.logger.Info("starting collection loop", "collection_interval", a.currentInterval().String())

	if err := a.performHealthCheck(ctx); err != nil {
		a.logger.Warn("initial health check failed", "error", err)
	}

	// Report once immediately, before entering the ticker loop. The server
	// creates the host when the first payload arrives, and the interval can be
	// as long as 10 minutes, during which a new install would look broken. The
	// startup jitter above keeps a mass restart from stampeding the server.
	if err := a.collectAndTransmit(ctx); err != nil {
		a.logger.Error("initial collection and transmission failed", "error", err)
	}

	ticker := time.NewTicker(a.currentInterval())
	defer ticker.Stop()

	// The delta tracker forgets metrics it has not seen for a day.
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	// Re-read the server config roughly hourly, jittered so a fleet does
	// not refresh in lockstep.
	configRefreshTicker := time.NewTicker(50*time.Minute + rand.N(20*time.Minute))
	defer configRefreshTicker.Stop()

	go a.runBackgroundUpdateChecks(ctx)

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("context cancelled, stopping agent")
			return ctx.Err()

		case <-a.stopChan:
			a.logger.Info("stop signal received, stopping agent")
			return nil

		case <-ticker.C:
			if err := a.collectAndTransmit(ctx); err != nil {
				a.logger.Error("collection and transmission failed", "error", err)
			}
			a.applyChangedConfig(ctx, ticker)

		case <-a.urgent:
			if err := a.collectAndTransmit(ctx); err != nil {
				a.logger.Error("early collection and transmission failed", "error", err)
			}
			a.applyChangedConfig(ctx, ticker)

		case <-cleanupTicker.C:
			if removed := a.deltaTracker.Cleanup(24 * time.Hour); removed > 0 {
				a.logger.Debug("delta tracker cleanup completed", "removed_metrics", removed)
			}

		case <-configRefreshTicker.C:
			old := a.currentInterval()
			if err := a.FetchRemoteConfig(ctx); err != nil {
				a.logger.Error("failed to refresh remote config; keeping current interval",
					"error", err,
					"hostname", a.hostname,
					"tenant_id", a.config.TenantID,
					"current_interval", old.String())
				continue
			}
			if interval := a.currentInterval(); interval != old {
				ticker.Reset(interval)
			}
		}
	}
}

// applyChangedConfig fetches the config when the last reply named a new
// settings revision, and moves the report ticker to a changed interval.
func (a *Agent) applyChangedConfig(ctx context.Context, ticker *time.Ticker) {
	if !a.configChanged(time.Now()) {
		return
	}
	old := a.currentInterval()
	if err := a.FetchRemoteConfig(ctx); err != nil {
		a.logger.Warn("settings changed on the server but the config could not be fetched; the next refresh retries", "error", err)
		return
	}
	a.logger.Info("applied settings changed on the server")
	if interval := a.currentInterval(); interval != old {
		ticker.Reset(interval)
	}
}

// requestReport asks the report loop for a cycle now. It never blocks: a
// request made while one is already pending is the same request.
func (a *Agent) requestReport() {
	select {
	case a.urgent <- struct{}{}:
	default:
	}
}

// runBackgroundUpdateChecks asks the OS package manager about pending updates
// on its own schedule, off the collection path, and caches the answer for the
// system collector to report.
func (a *Agent) runBackgroundUpdateChecks(ctx context.Context) {
	// Let the agent settle before the first (comparatively heavy) check.
	if err := sleep(ctx, 30*time.Second); err != nil {
		return
	}
	a.performUpdateCheck(ctx)

	ticker := time.NewTicker(updateCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopChan:
			return
		case <-ticker.C:
			a.performUpdateCheck(ctx)
		}
	}
}

// performUpdateCheck runs the update check and caches the result.
func (a *Agent) performUpdateCheck(ctx context.Context) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		return
	}

	systemCollector, ok := a.registry.GetCollector("system").(*system.Collector)
	if !ok {
		a.logger.Warn("system collector not available for update checks")
		return
	}

	updateCount, err := systemCollector.GetAvailableUpdates(ctx)
	if err != nil {
		a.logger.Warn("background update check failed", "error", err)
		return
	}

	securityUnknown := false
	securityCount, err := systemCollector.GetSecurityUpdates(ctx)
	if err != nil {
		a.logger.Warn("background security update check failed", "error", err)
		// The general count is still worth reporting; the security count is
		// left out rather than reported as zero.
		securityUnknown = true
	}

	cache.Set(system.UpdatesCacheKey(a.hostname), system.UpdateCounts{
		Available:       updateCount,
		Security:        securityCount,
		SecurityUnknown: securityUnknown,
		CheckedAt:       time.Now(),
	}, updateCheckInterval)

	a.logger.Info("background update check completed",
		"updates_available", updateCount,
		"security_updates", securityCount)
}

// collectAndTransmit performs one collection cycle and ships the result.
func (a *Agent) collectAndTransmit(ctx context.Context) error {
	started := time.Now()
	collected, err := a.registry.CollectAll(ctx)
	if err != nil {
		// A partial failure still leaves metrics worth sending.
		a.logger.Warn("partial collection failure", "error", err)
	}
	collected = append(collected, a.selfMetrics(time.Since(started))...)

	// Snapshots are staged by collectors during CollectAll and drained here.
	// A collector stages an inventory once per collection interval, which can
	// be hours, so the ones a failed post was carrying are offered again.
	snapshots := mergeSnapshots(a.undelivered, a.registry.Snapshots())

	if len(collected) == 0 && len(snapshots) == 0 {
		if err != nil {
			return fmt.Errorf("metric collection completely failed: %w", err)
		}
		return nil
	}

	if err := a.transmitMetrics(ctx, collected, snapshots); err != nil {
		a.mu.Lock()
		a.consecutiveFailures++
		a.mu.Unlock()
		return fmt.Errorf("metric transmission failed: %w", err)
	}

	a.mu.Lock()
	failures := a.consecutiveFailures
	a.consecutiveFailures = 0
	a.mu.Unlock()
	if failures > 0 {
		a.logger.Info("connection restored; resumed metric transmission",
			"previous_consecutive_failures", failures)
	}
	return nil
}

// cycleReporter is implemented by registries that record how each collector
// fared in the last cycle.
type cycleReporter interface {
	LastCycle() []registry.CollectorStatus
}

// selfMetrics describes the agent's own health for this cycle, so that a
// collector that fails or hangs on one host is visible on the platform and
// not only in that host's log:
//
//	agent_collector_up{collector}  1 when the collector returned in time
//	                               without an error, else 0
//	agent_collectors_failing       how many collectors are at 0: one number
//	                               per host for an alert to read
//	agent_collection_seconds       how long the cycle's collection took
//	agent_backlog_metrics          readings kept from failed posts, waiting
//	                               to be delivered
//
// The delta filter keeps an unchanged status from being sent every cycle.
func (a *Agent) selfMetrics(collection time.Duration) []metrics.Metric {
	reporter, ok := a.registry.(cycleReporter)
	if !ok {
		return nil
	}
	statuses := reporter.LastCycle()
	if len(statuses) == 0 {
		return nil
	}
	out := make([]metrics.Metric, 0, len(statuses)+3)
	failing := 0.0
	for _, s := range statuses {
		up := 0.0
		if s.OK {
			up = 1
		} else {
			failing++
		}
		out = append(out, metrics.QuickGaugeWithLabels(a.hostname, "agent_collector_up", up, map[string]string{"collector": s.Name}))
	}
	out = append(out, metrics.QuickGauge(a.hostname, "agent_collectors_failing", failing))
	// Tenths of a second: finer than that is noise the server would store.
	seconds := math.Round(collection.Seconds()*10) / 10
	return append(out,
		metrics.QuickGauge(a.hostname, "agent_collection_seconds", seconds),
		metrics.QuickGauge(a.hostname, "agent_backlog_metrics", float64(a.backlog.len())))
}

// transmitMetrics applies delta filtering and sends the result in batches.
//
// Snapshots bypass delta filtering (they are not time series) and ride along
// with the first batch only, so the server upserts each snapshot type once
// per cycle and runs its findings evaluator once rather than once per batch.
//
// Nothing a failed post carried is treated as delivered: its snapshots wait
// in a.undelivered, the delta filter forgets its metrics so that their next
// reading is sent whether or not the value moved, and the readings themselves
// wait in a.backlog.
//
// Kept readings ride in the same requests as fresh ones, filling the last
// batch, so catching up costs no extra request per cycle. They are not
// attached while posts are failing: an outage would otherwise be probed with
// an ever larger body. The first post that gets through is followed by one
// batch of kept readings, and the rest drain with the cycles after it.
func (a *Agent) transmitMetrics(ctx context.Context, all []metrics.Metric, snapshots []metrics.Snapshot) error {
	filtered := a.deltaTracker.FilterMetrics(all)
	a.logger.Debug("delta filtering completed",
		"total_metrics", len(all),
		"filtered_metrics", len(filtered),
		"snapshots", len(snapshots))

	a.mu.Lock()
	healthy := a.consecutiveFailures == 0
	a.mu.Unlock()

	var replayed []metrics.Metric
	switch {
	case healthy:
		replayed = a.backlog.take(replayRoom(len(filtered)), time.Now())
	case len(filtered) == 0 && len(snapshots) == 0 && !a.identityEnabled:
		// Nothing fresh to try the server with: kept readings are the probe.
		replayed = a.backlog.take(batchSize, time.Now())
	}
	if len(filtered) == 0 && len(replayed) == 0 && len(snapshots) == 0 && !a.identityEnabled {
		return nil
	}

	// Fresh readings first, so that when a post fails partway the split
	// between what was fresh and what was replayed is one index.
	sending := filtered
	if len(replayed) > 0 {
		sending = append(append(make([]metrics.Metric, 0, len(filtered)+len(replayed)), filtered...), replayed...)
	}
	batches := batch(sending, batchSize)
	if len(batches) == 0 {
		batches = [][]metrics.Metric{nil} // a snapshot-only cycle still needs one request
	}

	for i, b := range batches {
		var batchSnapshots []metrics.Snapshot
		var ack func()
		if i == 0 {
			batchSnapshots, ack = a.withExtras(snapshots, b)
		}

		start := time.Now()
		sendErr := a.transmitter.Send(ctx, b, batchSnapshots)
		if sendErr == nil && ack != nil {
			ack() // spool files are deleted only after a 2xx
			ack = nil
		}
		if sendErr == nil && i == 0 && len(snapshots) > 0 {
			a.ackSnapshots()
		}
		a.recordAttempt(start, sendErr)
		if i == 0 {
			if sendErr == nil {
				a.undelivered = nil
			} else {
				a.undelivered = snapshots
			}
		}
		if err := sendErr; err != nil {
			unsent := sending[min(i*batchSize, len(sending)):]
			fresh := unsent[:max(0, len(filtered)-i*batchSize)]
			a.deltaTracker.Forget(fresh)
			// A payload the server refuses would be refused again, and kept
			// readings ride with every later post. It is dropped.
			if !errors.Is(err, errPayloadRejected) {
				a.backlog.restore(unsent[len(fresh):])
				a.backlog.add(fresh)
			}
			return fmt.Errorf("failed to send batch %d of %d (%d metrics): %w", i+1, len(batches), len(b), err)
		}
		a.logger.Debug("batch sent",
			"batch", i+1,
			"of", len(batches),
			"metrics", len(b),
			"latency_ms", time.Since(start).Milliseconds())
	}
	if len(replayed) > 0 {
		a.logger.Info("delivered readings kept from failed posts",
			"delivered", len(replayed), "still_kept", a.backlog.len())
	} else if !healthy {
		a.deliverKept(ctx)
	}
	return nil
}

// deliverKept sends one batch of kept readings by itself, right after the
// first post that got through following failures. Its failure is not the
// cycle's: the cycle's own readings were delivered.
func (a *Agent) deliverKept(ctx context.Context) {
	kept := a.backlog.take(batchSize, time.Now())
	if len(kept) == 0 {
		return
	}
	if err := a.transmitter.Send(ctx, kept, nil); err != nil {
		if !errors.Is(err, errPayloadRejected) {
			a.backlog.restore(kept)
		}
		a.logger.Warn("could not deliver readings kept from failed posts; the next cycle retries",
			"readings", len(kept), "error", err)
		return
	}
	a.logger.Info("delivered readings kept from failed posts",
		"delivered", len(kept), "still_kept", a.backlog.len())
}

// replayRoom is how many kept readings ride with fresh ones this cycle: as
// many as fill the last batch. With no fresh readings that is one batch, so
// a quiet host still catches up.
func replayRoom(fresh int) int {
	return batchSize - fresh%batchSize
}

// maxWaitingDeltas bounds how many undelivered delta snapshots are kept, so a
// long outage cannot crowd everything else out of the 16-snapshot post.
const maxWaitingDeltas = 8

// mergeSnapshots returns the snapshots for this cycle: those still waiting
// from a failed post, then the freshly staged ones.
//
// Most snapshot types describe current state, so a fresh one supersedes a
// waiting one of the same type. k8s_health_delta is a list of transitions:
// each one counts, and they are kept in order.
func mergeSnapshots(waiting, fresh []metrics.Snapshot) []metrics.Snapshot {
	if len(waiting) == 0 {
		return fresh
	}
	staged := make(map[string]bool, len(fresh))
	for _, s := range fresh {
		staged[s.Type] = true
	}
	out := make([]metrics.Snapshot, 0, len(waiting)+len(fresh))
	deltas := 0
	for _, s := range waiting {
		if s.Type == metrics.SnapshotK8sHealthDelta {
			deltas++
			continue
		}
		if !staged[s.Type] {
			out = append(out, s)
		}
	}
	// The newest deltas win when there are more than the bound.
	skip := max(0, deltas-maxWaitingDeltas)
	for _, s := range waiting {
		if s.Type != metrics.SnapshotK8sHealthDelta {
			continue
		}
		if skip > 0 {
			skip--
			continue
		}
		out = append(out, s)
	}
	return append(out, fresh...)
}

// batch splits metrics into slices of at most size.
func batch(all []metrics.Metric, size int) [][]metrics.Metric {
	if len(all) == 0 {
		return nil
	}
	batches := make([][]metrics.Metric, 0, (len(all)+size-1)/size)
	for start := 0; start < len(all); start += size {
		end := min(start+size, len(all))
		batches = append(batches, all[start:end])
	}
	return batches
}

// performHealthCheck runs every collector's health check and logs the outcome.
func (a *Agent) performHealthCheck(ctx context.Context) error {
	results := a.registry.HealthCheck(ctx)

	var failures []string
	for name, err := range results {
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			a.logger.Warn("collector health check failed", "collector", name, "error", err)
		}
	}

	a.logger.Info("health check completed",
		"healthy", len(results)-len(failures),
		"total", len(results),
		"failed", len(failures))

	if len(failures) > 0 {
		return fmt.Errorf("health check failures: %v", failures)
	}
	return nil
}

// Stop asks the collection loop to exit. It is safe to call more than once.
func (a *Agent) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopChan)
	})
}

// Shutdown stops the loop and releases every resource the agent holds.
func (a *Agent) Shutdown(ctx context.Context) error {
	a.logger.Info("shutting down Netwarden agent")
	a.Stop()
	a.updater.Close()

	var errs []error
	if err := a.transmitter.Close(); err != nil {
		errs = append(errs, fmt.Errorf("transmitter shutdown error: %w", err))
	}
	if err := a.registry.Close(); err != nil {
		errs = append(errs, fmt.Errorf("registry shutdown error: %w", err))
	}
	if a.cacheCleanupStop != nil {
		close(a.cacheCleanupStop)
		a.cacheCleanupStop = nil
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	a.logger.Info("Netwarden agent shutdown completed")
	return nil
}
