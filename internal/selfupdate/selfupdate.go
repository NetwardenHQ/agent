// Package selfupdate decides whether, and when, the agent should install a
// newer release of itself.
//
// Trust model:
//
//   - The trigger is a version string carried in the ordinary /agent/data
//     reply. The agent already reports its version on every heartbeat, so
//     updates add no outbound destination (relevant where only the API host
//     is allowlisted) and no inbound channel.
//   - A locally configured self_update_url decides where to download from;
//     without one, the URL in the reply is used, so a self-hosted platform
//     can point its agents at its own repository. A forged reply can
//     therefore choose the download location, and nothing below trusts the
//     bytes because of where they came from.
//   - The digest the bytes must match comes from the API reply, not from the
//     download host, so a compromised download host alone cannot swap them.
//     A local mirror carries no vendor digest; see resolveTarget.
//   - The accepted signers are local-only (self_update_signers, or the
//     built-in pins). The server cannot add a signer.
//   - On Windows the installer's Authenticode signature, and then the version
//     embedded in it, are verified before it runs. On macOS and FreeBSD the
//     release manifest's signature over the version, platform and digest is
//     verified (release.go). That is the security boundary; everything else
//     is scheduling.
//
// How an update is applied depends on how the agent was installed:
//
//   - Windows: the signed installer runs silently.
//   - Linux packages: the agent asks for an upgrade and the netwarden-update
//     systemd service runs apt or dnf against the signed Netwarden
//     repository. The agent's own unit keeps forbidding it to write its
//     binary, and the package manager's signature check is the boundary.
//   - Kubernetes: the agent restarts, and the kubelet pulls the image again.
//   - macOS: the verified binary replaces the running one and launchd
//     restarts the agent.
//   - FreeBSD and OPNsense: a helper run through daemon(8) installs the
//     verified package with pkg(8) and restarts the service.
//
// Anything else (a manual install, a container outside Kubernetes, the
// Synology package, which runs unprivileged) reports self-update as
// unsupported and ignores hints.
package selfupdate

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// Defaults. The window is local time, chosen to land outside business hours;
// an update restarts the service, which briefly interrupts collection.
const (
	defaultWindowStartHour = 1
	defaultWindowEndHour   = 5
	// Don't retry the same version endlessly if it keeps failing to install.
	retryBackoff = 24 * time.Hour
	// maxSpread is the most an update is delayed to spread a fleet out.
	maxSpread = 30 * time.Minute
)

// Support describes whether this host can apply an update, and how.
type Support struct {
	// Available is false when nothing on this host can install an update.
	Available bool
	// Reason explains why an update is not available, for the log.
	Reason string
	// Download is true when the agent fetches and verifies the release
	// itself. On Linux packages the package manager does both.
	Download bool
}

// Reported states, sent to the platform with every payload so it knows which
// hosts keep themselves current.
const (
	StateEnabled     = "enabled"
	StateDisabled    = "disabled"
	StateUnsupported = "unsupported"
)

// Config controls the updater. Zero value is safe: disabled.
type Config struct {
	Enabled bool
	// WindowStartHour/WindowEndHour bound when an update may be applied, in
	// local time, 0-23. Start may be greater than end to span midnight.
	WindowStartHour int
	WindowEndHour   int
	// CurrentVersion is the version this binary was built as.
	CurrentVersion string

	// URLTemplate overrides the server's download URL entirely. Supports
	// {version}, {os} and {arch}. For airgapped sites and internal mirrors.
	URLTemplate string

	// Signers are the accepted code-signing identities (see signer.go for the
	// pin and name forms). Empty means the built-in list. This is the trust
	// anchor and is deliberately local-only: the server may say where to
	// download from, never whom to trust.
	Signers []string
}

// Updater holds the state between a hint arriving and an update being applied.
type Updater struct {
	cfg    Config
	logger *slog.Logger

	mu sync.Mutex
	// lastAttempt records when each version was last tried, so a release that
	// cannot install does not get retried on every heartbeat forever.
	lastAttempt map[string]time.Time
	inProgress  bool

	// ctx ends on Close, abandoning a scheduled update and cancelling a
	// running download.
	ctx    context.Context
	cancel context.CancelFunc

	// seams for tests
	support func() Support
	now     func() time.Time
	apply   func(ctx context.Context, target Target, signers []string, logger *slog.Logger) error
}

// acceptedSigners returns the configured signing subjects, or the built-in
// defaults when the operator has not overridden them.
func (c Config) acceptedSigners() []string {
	if len(c.Signers) > 0 {
		return c.Signers
	}
	return defaultSigners
}

// New returns an Updater for cfg. A zero window means the default
// maintenance window.
func New(cfg Config, logger *slog.Logger) *Updater {
	if cfg.WindowStartHour == 0 && cfg.WindowEndHour == 0 {
		cfg.WindowStartHour = defaultWindowStartHour
		cfg.WindowEndHour = defaultWindowEndHour
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Updater{
		cfg:         cfg,
		logger:      logger,
		lastAttempt: make(map[string]time.Time),
		ctx:         ctx,
		cancel:      cancel,
		support:     platformSupport,
		now:         time.Now,
		apply:       applyUpdate,
	}
}

// State reports whether this agent will apply updates on its own.
func (u *Updater) State() string {
	if u == nil {
		return ""
	}
	if !u.cfg.Enabled {
		return StateDisabled
	}
	if !u.support().Available {
		return StateUnsupported
	}
	return StateEnabled
}

// Close abandons any scheduled update and cancels one in progress. Safe on
// nil and safe to call more than once.
func (u *Updater) Close() {
	if u != nil {
		u.cancel()
	}
}

// ShouldApply reports whether hinted should be installed now and, if not,
// why. It depends only on the clock, so the policy is testable without a
// network or a filesystem.
func (u *Updater) ShouldApply(hinted string) (bool, string) {
	return u.decide(hinted, false)
}

// decide evaluates the policy. With claim set, a positive answer also marks
// the update in progress and records the attempt, in the same critical
// section as the checks: two hints arriving together cannot both pass.
func (u *Updater) decide(hinted string, claim bool) (bool, string) {
	if !u.cfg.Enabled {
		return false, "self-update disabled"
	}
	if sup := u.support(); !sup.Available {
		return false, sup.Reason
	}
	if hinted == "" {
		return false, "no version offered"
	}
	// Never sideways, never backwards: a downgrade is how a hostile or stale
	// hint would move a fleet onto a version with a known hole. This compares
	// the claim only; the installer's signed, embedded version is checked
	// again before it runs (checkInstallerVersion).
	if CompareVersions(hinted, u.cfg.CurrentVersion) <= 0 {
		return false, "offered version is not newer"
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.inProgress {
		return false, "update already in progress"
	}
	if last, ok := u.lastAttempt[hinted]; ok && u.now().Sub(last) < retryBackoff {
		return false, "recently attempted"
	}
	if !inWindow(u.now(), u.cfg.WindowStartHour, u.cfg.WindowEndHour) {
		return false, "outside maintenance window"
	}
	if claim {
		u.inProgress = true
		u.lastAttempt[hinted] = u.now()
	}
	return true, ""
}

// inWindow reports whether t's local hour falls in [start, end). A start
// greater than end spans midnight.
func inWindow(t time.Time, start, end int) bool {
	h := t.Hour()
	if start == end {
		return false
	}
	if start < end {
		return h >= start && h < end
	}
	return h >= start || h < end
}

// windowRemaining is how long until the window that t falls in closes. Only
// meaningful when inWindow(t, start, end).
func windowRemaining(t time.Time, end int) time.Duration {
	closes := time.Date(t.Year(), t.Month(), t.Day(), end, 0, 0, 0, t.Location())
	if !closes.After(t) {
		closes = closes.AddDate(0, 0, 1)
	}
	return closes.Sub(t)
}

// spreadDelay picks the random delay that spreads a fleet out, bounded so
// the install still starts inside the maintenance window.
func spreadDelay(remaining time.Duration) time.Duration {
	limit := min(maxSpread, remaining)
	if limit <= 0 {
		return 0
	}
	return rand.N(limit)
}

// resolve turns an offer into a target. Where the package manager fetches
// the release, only the version matters, and it still has to be a shape a
// release can produce.
func (u *Updater) resolve(offer Offer) (Target, error) {
	if u.support().Download {
		return resolveTarget(offer, u.cfg)
	}
	if !safeVersion(offer.Version) {
		return Target{}, fmt.Errorf("refusing unsafe version string %q", offer.Version)
	}
	return Target{Version: offer.Version, Current: u.cfg.CurrentVersion}, nil
}

// HandleHint is the callback the transmitter invokes. It returns at once; the
// download and install run on their own goroutine so a slow download cannot
// hold up metric collection.
func (u *Updater) HandleHint(offer Offer) {
	version := offer.Version
	ok, reason := u.ShouldApply(version)
	if !ok {
		u.logger.Debug("update hint not actioned", "offered", version,
			"current", u.cfg.CurrentVersion, "reason", reason)
		return
	}

	target, err := u.resolve(offer)
	if err != nil {
		u.logger.Warn("update hint rejected", "offered", version, "error", err)
		return
	}

	// Re-check and claim atomically: the check above was advisory.
	if ok, reason := u.decide(version, true); !ok {
		u.logger.Debug("update hint not actioned", "offered", version, "reason", reason)
		return
	}
	delay := spreadDelay(windowRemaining(u.now(), u.cfg.WindowEndHour))

	go func() {
		defer func() {
			u.mu.Lock()
			u.inProgress = false
			u.mu.Unlock()
		}()

		// Spread the fleet out, so a large fleet neither floods the download
		// host nor restarts all its services at the same moment.
		u.logger.Info("agent update scheduled", "version", version, "delay", delay)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-u.ctx.Done():
			u.logger.Info("scheduled agent update abandoned: agent stopping", "version", version)
			return
		}

		ctx, cancel := context.WithTimeout(u.ctx, 30*time.Minute)
		defer cancel()

		if err := u.apply(ctx, target, u.cfg.acceptedSigners(), u.logger); err != nil {
			u.logger.Error("agent update failed", "version", version, "error", err)
			return
		}
		u.logger.Info("agent update applied", "version", version)
	}()
}
