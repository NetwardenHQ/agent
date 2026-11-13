//go:build !windows

package postgresql

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/dsm"
)

// DSM runs a PostgreSQL of its own for Synology's apps, which the owner
// neither manages nor can connect to; reporting it as a database that fails
// to connect is noise.
func TestDSMOwnPostgreSQLIsLeftAlone(t *testing.T) {
	old := dsm.Marker
	dsm.Marker = filepath.Join(t.TempDir(), "synoinfo.conf")
	t.Cleanup(func() { dsm.Marker = old })
	if err := os.WriteFile(dsm.Marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if NewCollector(config.DatabaseConfig{}, "nas").ownedByUser() {
		t.Error("DSM's own PostgreSQL taken as the owner's")
	}
	if !NewCollector(config.DatabaseConfig{PostgreSQLHost: "127.0.0.1:5433"}, "nas").ownedByUser() {
		t.Error("a PostgreSQL the owner configured was ignored on DSM")
	}
}
