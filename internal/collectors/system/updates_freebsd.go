//go:build freebsd

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// pkgTimeout bounds each pkg(8) call; both read only local databases.
const pkgTimeout = 30 * time.Second

// GetAvailableUpdates returns the number of installed packages that are older
// than the version in the repository catalog (`pkg version -RU -vl '<'`,
// one line per outdated package).
//
// -R compares against the repository catalog; without it pkg prefers a ports
// tree or INDEX file when one exists. -U reads the catalog as last fetched
// instead of refreshing it, so the network is never touched and on OPNsense
// the count matches the last firmware check.
func (c *Collector) GetAvailableUpdates(ctx context.Context) (int, error) {
	out, err := runPkg(ctx, "version", "-R", "-U", "-v", "-l", "<")
	if err != nil {
		return 0, fmt.Errorf("pkg version: %w", err)
	}
	return countLines(out), nil
}

// GetSecurityUpdates returns the number of installed packages that `pkg audit`
// reports as vulnerable, using the local vulnerability database. This counts
// vulnerable packages, not available security updates: a vulnerable package
// may have no fixed version yet. (The method name is the cross-platform
// interface's.) A missing database is an error, not zero: "no data" must not
// read as "no problems".
func (c *Collector) GetSecurityUpdates(ctx context.Context) (int, error) {
	out, err := runPkg(ctx, "audit", "-q")
	if err == nil {
		return countLines(out), nil
	}
	// pkg audit exits 1 when it found vulnerable packages; that is the result.
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 && len(bytes.TrimSpace(out)) > 0 {
		return countLines(out), nil
	}
	return 0, fmt.Errorf("pkg audit: %w", err)
}

// runPkg runs pkg(8) and returns its stdout. pkg exits 0 for `version` even
// when it could not open a repository catalog and printed nothing useful, so
// stderr is checked too: an unreadable catalog is an error, never "0 updates".
func runPkg(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, pkgTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pkg", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil && bytes.Contains(stderr.Bytes(), []byte("'pkg update' required")) {
		return nil, errors.New("repository catalog missing, run pkg update")
	}
	if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), err
}

func countLines(b []byte) int {
	n := 0
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			n++
		}
	}
	return n
}
