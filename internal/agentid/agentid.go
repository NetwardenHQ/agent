// Package agentid keeps the id of this agent installation.
//
// The server used to tell hosts apart by hostname alone, so a renamed machine
// showed up as a second host and the first one went quiet. The id is what
// stays the same: a random UUID generated on the first start and sent with
// every report.
//
// It has a file of its own, apart from netwarden.conf, because installers
// rewrite the config file. It is random rather than derived from the machine
// (machine-id, hardware UUID): cloned machines share those, and two machines
// must never share an id.
package agentid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// fileName is the id file, kept in the agent's state directory.
const fileName = "agent-id"

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Valid reports whether id has the form the server accepts: a lowercase UUID.
func Valid(id string) bool { return idPattern.MatchString(id) }

// Env is what decides where the id is kept.
type Env struct {
	GOOS        string
	ProgramData string // %ProgramData%, Windows only
	ConfigFile  string // path of the loaded netwarden.conf
	DSM         bool   // running as a Synology package
	Kubernetes  bool   // running in a pod
}

// Path returns the id file for this platform: the state directory the agent
// already uses there. It returns "" where nothing the agent can write
// outlives a restart, and the agent then sends no id.
func Path(env Env) string {
	switch env.GOOS {
	case "linux":
		// A pod's filesystem is gone with the pod, and a new id on every
		// start would be worse than none. The server keeps identifying a
		// cluster agent by the hostname its Deployment configures.
		if env.Kubernetes {
			return ""
		}
		// DSM runs the agent as the package user, which cannot create
		// /var/lib/netwarden. The package's data folder, where the config
		// file is, survives upgrades.
		if env.DSM {
			if env.ConfigFile == "" {
				return ""
			}
			return filepath.Join(filepath.Dir(env.ConfigFile), fileName)
		}
		return "/var/lib/netwarden/" + fileName
	case "darwin":
		return "/var/lib/netwarden/" + fileName
	case "freebsd":
		return "/var/db/netwarden/" + fileName
	case "windows":
		programData := env.ProgramData
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "Netwarden", fileName)
	}
	return ""
}

// Load returns the id stored at path, generating and storing one on the
// first start.
//
// It returns an id only when that id is on disk. If the file exists but
// cannot be read, or a new id cannot be written, Load returns an error and no
// id: an id that changed on every start would make every start a new host. A
// file that is readable but holds no id is replaced.
func Load(path string) (string, error) {
	if path == "" {
		return "", errors.New("no persistent state directory on this platform")
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if id := strings.ToLower(strings.TrimSpace(string(raw))); Valid(id) {
			return id, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("read agent id: %w", err)
	}

	id, err := generate()
	if err != nil {
		return "", fmt.Errorf("generate agent id: %w", err)
	}
	if err := store(path, id); err != nil {
		return "", fmt.Errorf("store agent id: %w", err)
	}
	return id, nil
}

// generate returns a random (version 4) UUID.
func generate() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// store writes the id through a temporary file and a rename, so a crash
// leaves either the old file or the new one.
func store(path, id string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+fileName+"-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(id + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
