//go:build linux || darwin || windows || freebsd

package security

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// maxIncludeFiles caps how many files are resolved from a single Include
// directive (one level of nesting), to bound work on hosts with sprawling
// drop-in directories.
const maxIncludeFiles = 64

// Enabled reports whether the SSH config collector should run. It always
// does; a missing file is handled at collect time.
func (c *SSHConfigCollector) Enabled() bool {
	return true
}

// Collect parses sshd_config (with one level of Include resolution) and emits
// posture metrics. The directive syntax is identical across OpenSSH ports, so
// this implementation is shared by Linux, macOS, and the Windows OpenSSH
// server; only the config path differs (see sshdConfigPath). Parsing runs at
// most once per sshConfigInterval; in between, the previous metrics are
// re-emitted with a fresh timestamp.
func (c *SSHConfigCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	now := time.Now()

	c.mu.Lock()
	throttled := !c.lastCollected.IsZero() && now.Sub(c.lastCollected) < sshConfigInterval && len(c.lastMetrics) > 0
	if throttled {
		// Refresh timestamps on cached metrics so the series stays
		// continuous between parses.
		refreshed := make([]metrics.Metric, len(c.lastMetrics))
		for i, m := range c.lastMetrics {
			m.Timestamp = now
			refreshed[i] = m
		}
		c.mu.Unlock()
		return refreshed, nil
	}
	c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	configPath := sshdConfigPath()
	findings, err := c.parseSSHDConfig(configPath)
	if err != nil {
		// Missing or unreadable file: emit nothing this cycle, log once.
		c.missingLogOnce.Do(func() {
			c.logger.Info("sshd_config not readable; SSH posture metrics will be skipped",
				"path", configPath,
				"error", err,
				"hint", "this is normal on hosts without an SSH server installed")
		})
		return nil, nil
	}

	out := c.emitMetrics(findings, now)

	snap := buildSSHConfigSnapshot(findings)

	c.mu.Lock()
	c.lastCollected = now
	c.lastMetrics = out
	c.pending = &snap
	c.mu.Unlock()

	c.logger.Debug("ssh config audited",
		"permit_root", findings.PermitRootLogin,
		"password_auth", findings.PasswordAuth,
		"protocol_v1", findings.ProtocolV1,
		"x11", findings.X11Forwarding,
		"empty_pw", findings.PermitEmptyPass,
		"port", findings.Port)

	return out, nil
}

// parseSSHDConfig reads the primary sshd_config and any Include'd drop-in
// files (one level deep) and returns the resolved posture findings.
//
// sshd uses the first value for most directives, so the include chain is
// walked in sshd's order and each directive is pinned once set.
func (c *SSHConfigCollector) parseSSHDConfig(path string) (sshConfigFindings, error) {
	primary, err := os.Open(path)
	if err != nil {
		return sshConfigFindings{}, err
	}

	// Defaults reflect sshd's compiled-in defaults so an unset directive
	// still maps to a sensible posture value.
	f := sshConfigFindings{
		PermitRootLogin: true, // OpenSSH default since 7.0 is "prohibit-password", but
		// distros frequently override it to "yes", so unset is reported
		// as insecure to prompt setting it explicitly.
		PasswordAuth:    true,  // default yes
		ProtocolV1:      false, // long retired; default is no
		X11Forwarding:   false, // default no
		PermitEmptyPass: false, // default no
		Port:            "22",
		SourceFile:      path,
	}

	// Directives already pinned (first match wins).
	seen := map[string]bool{}

	type stream struct {
		path string
		rc   *os.File
	}
	queue := []stream{{path: path, rc: primary}}

	// sshd resolves every relative Include against its config directory
	// (SSHDIR, /etc/ssh on stock builds), whichever file holds the
	// directive. The primary config lives in that directory.
	sshDir := filepath.Dir(path)

	processed := 0
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]

		includes := c.parseStream(sshDir, head.rc, &f, seen)
		_ = head.rc.Close()

		for _, inc := range includes {
			if processed >= maxIncludeFiles {
				c.logger.Debug("sshd Include cap reached", "max", maxIncludeFiles)
				break
			}
			processed++
			rc, err := os.Open(inc)
			if err != nil {
				c.logger.Debug("failed to open included sshd config", "path", inc, "error", err)
				continue
			}
			queue = append(queue, stream{path: inc, rc: rc})
		}
	}

	return f, nil
}

// parseStream parses a single sshd_config-format reader into f. Returns the
// list of expanded paths from any Include directives encountered, with
// relative paths resolved against sshDir.
func (c *SSHConfigCollector) parseStream(sshDir string, rc *os.File, f *sshConfigFindings, seen map[string]bool) []string {
	var includes []string

	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 16*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments (sshd_config supports them).
		if hash := strings.Index(line, " #"); hash >= 0 {
			line = strings.TrimSpace(line[:hash])
		}

		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		lkey := strings.ToLower(key)

		// Include is collected, not pinned.
		if lkey == "include" {
			includes = append(includes, expandIncludes(sshDir, value)...)
			continue
		}

		if seen[lkey] {
			continue
		}

		switch lkey {
		case "permitrootlogin":
			seen[lkey] = true
			f.PermitRootLogin = isPermitRootInsecure(value)
		case "passwordauthentication":
			seen[lkey] = true
			f.PasswordAuth = isYes(value)
		case "protocol":
			seen[lkey] = true
			f.ProtocolV1 = strings.Contains(value, "1")
		case "x11forwarding":
			seen[lkey] = true
			f.X11Forwarding = isYes(value)
		case "permitemptypasswords":
			seen[lkey] = true
			f.PermitEmptyPass = isYes(value)
		case "port":
			// Take the first explicit Port directive.
			if !seen[lkey] {
				seen[lkey] = true
				f.Port = value
			}
		case "kexalgorithms":
			if !seen[lkey] {
				seen[lkey] = true
				f.KexAlgorithms = value
			}
		case "ciphers":
			if !seen[lkey] {
				seen[lkey] = true
				f.Ciphers = value
			}
		case "macs":
			if !seen[lkey] {
				seen[lkey] = true
				f.MACs = value
			}
		}
	}

	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		c.logger.Debug("scanner error reading sshd config", "path", rc.Name(), "error", err)
	}

	return includes
}

// splitDirective splits a sshd_config line into its key and value portion.
// sshd_config uses whitespace as a separator and allows '=' as well.
func splitDirective(line string) (key, value string, ok bool) {
	// Try whitespace split first.
	for i, r := range line {
		if r == ' ' || r == '\t' || r == '=' {
			key = line[:i]
			value = strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
			if key == "" {
				return "", "", false
			}
			return key, value, true
		}
	}
	return "", "", false
}

// expandIncludes turns one Include directive value (which can list multiple
// paths and contain glob patterns) into a concrete list of files to read.
// Relative paths resolve against sshDir, the ssh config directory.
func expandIncludes(sshDir, value string) []string {
	var out []string
	// sshd allows whitespace-separated lists.
	for _, raw := range strings.Fields(value) {
		// Strip surrounding quotes if any.
		raw = strings.Trim(raw, `"`)
		if raw == "" {
			continue
		}
		// sshd_config(5): "Files without absolute paths are assumed to be
		// in /etc/ssh", the config directory, even when the Include sits
		// in an included file elsewhere.
		if !filepath.IsAbs(raw) {
			raw = filepath.Join(sshDir, raw)
		}

		matches, err := filepath.Glob(raw)
		if err != nil || len(matches) == 0 {
			// If glob returns nothing, but the literal exists, fall back.
			if _, err := os.Stat(raw); err == nil {
				out = append(out, raw)
			}
			continue
		}
		out = append(out, matches...)
	}
	return out
}

// isYes returns true for sshd_config truthy values.
func isYes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// isPermitRootInsecure interprets PermitRootLogin per sshd semantics:
//   - "yes" / unset on legacy distros => insecure (1)
//   - "no", "prohibit-password", "without-password", "forced-commands-only" => secure (0)
func isPermitRootInsecure(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "no", "prohibit-password", "without-password", "forced-commands-only":
		return false
	default:
		// "yes" and unrecognized values are treated as insecure.
		return true
	}
}
