//go:build linux

package security

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// collectLanguagePackages discovers host-installed language packages under the
// given roots plus the auto-discovered Python site-packages locations.
//
// extraRoots are operator-configured directories to scan for node_modules and
// site-packages (e.g. an app deploy path). Python system locations are always
// discovered because they are bounded and well-known; Node is scanned only
// under extraRoots or a discovered site, because node_modules can live
// anywhere and a system-wide search would be unbounded.
//
// truncated reports that the walk stopped at a cap, the time budget or the
// context deadline before covering every root, so the inventory is partial:
// a package missing from it may still be installed.
func collectLanguagePackages(ctx context.Context, extraRoots []string) (pkgs []installedPackage, truncated bool) {
	stats := &walkStats{deadline: time.Now().Add(langWalkBudget)}

	// Deduplicate roots and drop missing ones so no tree is walked twice.
	roots := dedupeExistingDirs(append(discoverPythonSiteDirs(), extraRoots...))

	var out []installedPackage
	seen := map[string]struct{}{} // ecosystem|name|version

	add := func(pkgs []installedPackage) {
		for _, p := range pkgs {
			if stats.packages >= maxLangPackages {
				return
			}
			key := p.Ecosystem + "|" + p.Name + "|" + p.Version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, p)
			stats.packages++
		}
	}

	for _, root := range roots {
		if stats.exhausted() || ctx.Err() != nil {
			break
		}
		add(scanRoot(ctx, root, stats))
	}

	return out, stats.exhausted() || ctx.Err() != nil
}

// scanRoot walks one root looking for python dist-info/egg-info and
// node_modules package manifests. It descends at most maxWalkDepth and stops
// the moment a global cap trips.
func scanRoot(ctx context.Context, root string, stats *walkStats) []installedPackage {
	var pkgs []installedPackage

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxWalkDepth || stats.exhausted() || ctx.Err() != nil {
			return
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, e := range entries {
			if stats.exhausted() {
				return
			}
			stats.dirEntries++
			name := e.Name()

			// Never follow symlinked directories: they can loop or escape
			// the root.
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}

			if !e.IsDir() {
				continue
			}

			full := filepath.Join(dir, name)

			switch {
			case strings.HasSuffix(name, ".dist-info"):
				if p, ok := readPythonMetadata(filepath.Join(full, "METADATA")); ok {
					pkgs = append(pkgs, p)
				}
			case strings.HasSuffix(name, ".egg-info"):
				if p, ok := readPythonMetadata(filepath.Join(full, "PKG-INFO")); ok {
					pkgs = append(pkgs, p)
				}
			case name == "node_modules":
				pkgs = append(pkgs, scanNodeModules(full, stats)...)
				// Do not also recurse into node_modules generically; scanNodeModules
				// handles its (bounded) structure.
			default:
				walk(full, depth+1)
			}
		}
	}

	walk(root, 0)
	return pkgs
}

// scanNodeModules reads name+version from each package directly under a
// node_modules directory, including one level of @scope. It does not recurse
// into nested node_modules, which hold transitive dependencies and grow
// combinatorially.
func scanNodeModules(nodeModules string, stats *walkStats) []installedPackage {
	var pkgs []installedPackage

	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if stats.exhausted() {
			return pkgs
		}
		stats.dirEntries++
		name := e.Name()
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() || name == ".bin" {
			continue
		}

		if strings.HasPrefix(name, "@") {
			// Scoped packages: one more level, e.g. @types/node.
			scopeDir := filepath.Join(nodeModules, name)
			scoped, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, se := range scoped {
				if stats.exhausted() {
					return pkgs
				}
				stats.dirEntries++
				if se.Type()&os.ModeSymlink != 0 || !se.IsDir() {
					continue
				}
				if p, ok := readNodePackage(filepath.Join(scopeDir, se.Name(), "package.json")); ok {
					pkgs = append(pkgs, p)
				}
			}
			continue
		}

		if p, ok := readNodePackage(filepath.Join(nodeModules, name, "package.json")); ok {
			pkgs = append(pkgs, p)
		}
	}

	return pkgs
}

// readNodePackage extracts name+version from a package.json.
func readNodePackage(path string) (installedPackage, bool) {
	data, ok := readManifest(path)
	if !ok {
		return installedPackage{}, false
	}
	var pj struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return installedPackage{}, false
	}
	if pj.Name == "" || pj.Version == "" {
		return installedPackage{}, false
	}
	return installedPackage{
		Name:      pj.Name,
		Version:   pj.Version,
		Ecosystem: EcosystemNPM,
		Source:    "node_modules",
	}, true
}

// readPythonMetadata parses the RFC 822-style METADATA / PKG-INFO header for
// Name and Version. Only the leading header block is read; the body (which can
// be a long README) is ignored.
func readPythonMetadata(path string) (installedPackage, bool) {
	f, ok := openManifest(path)
	if !ok {
		return installedPackage{}, false
	}
	defer f.Close()

	var name, version string
	sc := bufio.NewScanner(io.LimitReader(f, maxManifestBytes))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of header block
		}
		if v, ok := cutHeader(line, "Name:"); ok && name == "" {
			name = v
		} else if v, ok := cutHeader(line, "Version:"); ok && version == "" {
			version = v
		}
		if name != "" && version != "" {
			break
		}
	}
	if name == "" || version == "" {
		return installedPackage{}, false
	}
	return installedPackage{
		Name:      name,
		Version:   version,
		Ecosystem: EcosystemPyPI,
		Source:    "site-packages",
	}, true
}

// cutHeader returns the trimmed value when line starts with the given header
// key (case-insensitive), matching how pip writes these fields.
func cutHeader(line, key string) (string, bool) {
	if len(line) < len(key) {
		return "", false
	}
	if !strings.EqualFold(line[:len(key)], key) {
		return "", false
	}
	return strings.TrimSpace(line[len(key):]), true
}

// readManifest reads a small manifest file, capped, returning false on any
// error or on an empty file.
func readManifest(path string) ([]byte, bool) {
	f, ok := openManifest(path)
	if !ok {
		return nil, false
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes))
	if err != nil || len(data) == 0 {
		return nil, false
	}
	return data, true
}

// openManifest opens a manifest only if it is a regular file, without
// following a symlink and without blocking. The walk runs as root over trees
// any local user may write to, so a planted package.json can be a symlink to
// a file outside the root or a FIFO, and a plain open(2) of a FIFO with no
// writer never returns. Lstat rejects both up front; O_NOFOLLOW|O_NONBLOCK
// covers a swap between the Lstat and the open, and the Fstat confirms the
// opened file is still the regular file that was checked.
func openManifest(path string) (*os.File, bool) {
	lst, err := os.Lstat(path)
	if err != nil || !lst.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	fst, err := f.Stat()
	if err != nil || !fst.Mode().IsRegular() || !os.SameFile(lst, fst) {
		f.Close()
		return nil, false
	}
	return f, true
}

// discoverPythonSiteDirs returns the well-known system site-packages /
// dist-packages directories that exist on this host. It expands a fixed set
// of glob patterns and does no free traversal.
func discoverPythonSiteDirs() []string {
	patterns := []string{
		"/usr/lib/python3*/site-packages",
		"/usr/lib/python3*/dist-packages",
		"/usr/lib64/python3*/site-packages",
		"/usr/local/lib/python3*/site-packages",
		"/usr/local/lib/python3*/dist-packages",
		"/opt/homebrew/lib/python3*/site-packages", // macOS
		"/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
	}
	var dirs []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		dirs = append(dirs, matches...)
	}
	return dirs
}

// dedupeExistingDirs returns the distinct, cleaned paths that exist and are
// directories.
func dedupeExistingDirs(paths []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if _, dup := seen[clean]; dup {
			continue
		}
		info, err := os.Stat(clean)
		if err != nil || !info.IsDir() {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out
}
