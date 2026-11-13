// Package dsm answers whether the agent runs on Synology DSM, and what DSM's
// version file says. Several collectors behave differently there: DSM runs
// the agent as an unprivileged package user, keeps its version outside
// /etc/os-release and runs a PostgreSQL of its own.
package dsm

import (
	"bufio"
	"os"
	"strings"
)

// Marker exists only on DSM. A variable so tests can point it elsewhere.
var Marker = "/etc.defaults/synoinfo.conf"

// VersionFile is DSM's equivalent of /etc/os-release.
var VersionFile = "/etc.defaults/VERSION"

// Is reports whether this host runs DSM.
func Is() bool {
	_, err := os.Stat(Marker)
	return err == nil
}

// Version returns DSM's product version ("7.4.1") and build number from
// VersionFile, or "" when it cannot be read.
func Version() (version, build string) {
	f, err := os.Open(VersionFile)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "productversion":
			version = v
		case "buildnumber":
			build = v
		}
	}
	return version, build
}
