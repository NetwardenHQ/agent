package fim

import (
	"context"
	"os"
	"path/filepath"
)

// Walk caps. FIM roots are meant to be tight and high-signal, but an operator
// can point FIM at a large tree, so the walk is bounded the same way the
// language-package walker is. Hitting a cap ends the walk early: the result is
// marked truncated, files it did reach are diffed as usual, and baseline files
// in places it never reached are carried over rather than reported deleted.
const (
	// maxEntries caps total files recorded across all roots.
	maxEntries = 50000

	// maxDirEntries caps directory entries examined per walk, the backstop
	// against a pathological or looping tree.
	maxDirEntries = 500000

	// maxWalkDepth bounds recursion. The default ruleset is shallow; a deep
	// bound still captures it while refusing to descend arbitrarily. It is a
	// scope limit, not a cap: deeper files are not watched.
	maxWalkDepth = 12
)

// walkResult is one walk's output.
type walkResult struct {
	entries map[string]Entry

	// truncated is set when a cap ended the walk before it had seen
	// everything under its roots.
	truncated bool

	// examined holds every directory whose listing was read to the end, and
	// every path (root or directory) that was looked up and found missing. A
	// baseline file absent from entries is a deletion only if the nearest
	// existing ancestor directory is in this set (see covers).
	examined map[string]struct{}

	// rootDev is each root's device, for the real-time scope check.
	rootDev map[string]uint64
}

// covers reports whether the walk looked where path would have been, so that
// its absence from entries really means it is gone.
func (r *walkResult) covers(path string) bool {
	if _, ok := r.examined[path]; ok {
		return true // a single-file root that was looked up and is missing
	}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		if _, ok := r.examined[d]; ok {
			return true
		}
		if _, err := os.Lstat(d); err == nil {
			return false // exists, but its listing was not completed
		}
		if parent := filepath.Dir(d); parent == d {
			return false
		}
	}
}

// walkState tracks a walk against its caps and against a set of visited real
// paths, so a symlink or bind mount cannot make the walk revisit a subtree.
type walkState struct {
	res        *walkResult
	dirEntries int
	visited    map[string]struct{}

	// dev is the current root's device; the walk does not cross into other
	// mounts beneath it.
	dev    uint64
	hasDev bool
}

func (st *walkState) capped() bool {
	if st.dirEntries >= maxDirEntries || len(st.res.entries) >= maxEntries {
		st.res.truncated = true
		return true
	}
	return false
}

// buildEntries walks the given roots and returns the recorded file state,
// keyed by absolute path. Never follows symlinks, never leaves a root's
// filesystem, and skips kernel pseudo-filesystems. Only regular files are
// recorded; directories, devices, sockets and FIFOs are structure, not content
// to baseline. A walk ended by ctx is incomplete in ways the result cannot
// describe; the caller must discard it.
func buildEntries(ctx context.Context, roots []string) *walkResult {
	res := &walkResult{
		entries:  make(map[string]Entry),
		examined: make(map[string]struct{}),
		rootDev:  make(map[string]uint64),
	}
	st := &walkState{res: res, visited: map[string]struct{}{}}

	for _, root := range roots {
		if ctx.Err() != nil || st.capped() {
			break
		}
		st.dev, st.hasDev = 0, false
		if info, err := os.Lstat(root); err == nil {
			st.dev, st.hasDev = deviceOf(info)
			if st.hasDev {
				res.rootDev[root] = st.dev
			}
		}
		walkRoot(ctx, root, 0, st)
	}
	return res
}

func walkRoot(ctx context.Context, dir string, depth int, st *walkState) {
	if ctx.Err() != nil || depth > maxWalkDepth || st.capped() || isPseudoFS(dir) {
		return
	}
	out := st.res.entries

	// A root may itself be a single file (e.g. /etc/sudoers), not a directory.
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			st.res.examined[dir] = struct{}{}
		}
		return
	}
	if info.Mode().IsRegular() {
		if e, ok := recordFile(ctx, dir, info); ok {
			out[dir] = e
		}
		st.res.examined[dir] = struct{}{}
		return
	}
	if !info.IsDir() {
		return
	}
	if st.hasDev {
		if dev, ok := deviceOf(info); ok && dev != st.dev {
			return // a different filesystem mounted under the root
		}
	}

	// Guard against revisiting the same real directory via a link.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		real = dir
	}
	if _, seen := st.visited[real]; seen {
		return
	}
	st.visited[real] = struct{}{}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, de := range dirEntries {
		if ctx.Err() != nil || st.capped() {
			return
		}
		st.dirEntries++

		full := filepath.Join(dir, de.Name())

		// Never follow symlinks: they are the classic unbounded-walk escape.
		if de.Type()&os.ModeSymlink != 0 {
			continue
		}
		if de.IsDir() {
			walkRoot(ctx, full, depth+1, st)
			continue
		}
		if !de.Type().IsRegular() {
			continue // devices, sockets, FIFOs
		}

		fi, err := de.Info()
		if err != nil {
			continue
		}
		if e, ok := recordFile(ctx, full, fi); ok {
			out[full] = e
		}
	}
	st.res.examined[dir] = struct{}{}
}
