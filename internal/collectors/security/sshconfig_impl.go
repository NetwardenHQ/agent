//go:build linux || darwin || windows

package security

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netwarden/internal/metrics"
)

// maxIncludeFiles caps how many files we resolve from a single Include
// directive (one level of nesting), to bound work on hosts with sprawling
// drop-in directories.
const maxIncludeFiles = 64

// Enabled reports whether the SSH config collector should run. We're enabled
// on Linux unconditionally; missing files are handled at collect time.
func (c *SSHConfigCollector) Enabled() bool {
	return true
}

// Collect parses sshd_config (with one level of Include resolution) and emits
// posture metrics. The directive syntax is identical across OpenSSH ports, so
// this implementation is shared by Linux, macOS, and the Windows OpenSSH
// server; only the config path differs (see sshdConfigPath). The work is throttled to once per sshConfigInterval; on
// intervening cycles the previous metrics are re-emitted with a fresh timestamp.
func (c *SSHConfigCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	now := time.Now()

	c.mu.Lock()
	throttled := !c.lastCollected.IsZero() && now.Sub(c.lastCollected) < sshConfigInterval && len(c.lastMetrics) > 0
	if throttled {
		// Refresh timestamps on cached metrics so dashboards keep the
		// stream live even though we don't re-parse.
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
		// Missing/unreadable file — emit nothing this cycle, log once.
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
// sshd uses first-match-wins for most directives, so we walk the include
// chain in the same order sshd would and stop tracking each directive once
// it has been set.
func (c *SSHConfigCollector) parseSSHDConfig(path string) (sshConfigFindings, error) {
	primary, err := os.Open(path)
	if err != nil {
		return sshConfigFindings{}, err
	}

	// Defaults reflect sshd's compiled-in defaults so an unset directive
	// still maps to a sensible posture value.
	f := sshConfigFindings{
		PermitRootLogin: true, // OpenSSH default since 7.0 is "prohibit-password" but
		// distros frequently override to "yes". We treat *unset* as
		// noteworthy=1 so operators are nudged to set it explicitly;
		// most hardened distros do.
		PasswordAuth:    true,  // default yes
		ProtocolV1:      false, // long retired; default is no
		X11Forwarding:   false, // default no
		PermitEmptyPass: false, // default no
		Port:            "22",
		SourceFile:      path,
	}

	// Track which directives we've already pinned (first-match-wins).
	seen := map[string]bool{}

	type stream struct {
		path string
		rc   *os.File
	}
	queue := []stream{{path: path, rc: primary}}

	processed := 0
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]

		includes := c.parseStream(head.path, head.rc, &f, seen)
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
// list of expanded paths from any Include directives encountered (callers
// may decide to walk them — only the top-level call should, per the spec's
// "one level of nesting" rule).
func (c *SSHConfigCollector) parseStream(path string, rc *os.File, f *sshConfigFindings, seen map[string]bool) []string {
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

		// Include is special — collect, don't pin.
		if lkey == "include" {
			includes = append(includes, expandIncludes(path, value)...)
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
		c.logger.Debug("scanner error reading sshd config", "path", path, "error", err)
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
// paths and contain glob patterns, with paths relative to /etc/ssh) into a
// concrete list of files to read.
func expandIncludes(parentPath, value string) []string {
	var out []string
	// sshd allows whitespace-separated lists.
	for _, raw := range strings.Fields(value) {
		// Strip surrounding quotes if any.
		raw = strings.Trim(raw, `"`)
		if raw == "" {
			continue
		}
		// Resolve relative paths against the parent file's directory
		// (sshd_config quirk: "If the path is relative, it's relative to
		// the location of the file that contains the Include directive,
		// or /etc/ssh if at top level.").
		if !filepath.IsAbs(raw) {
			raw = filepath.Join(filepath.Dir(parentPath), raw)
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
		// "yes" or anything we don't recognize is treated as the
		// noteworthy / potentially-insecure case.
		return true
	}
}
