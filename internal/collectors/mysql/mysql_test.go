package mysql

import (
	"testing"

	driver "github.com/go-sql-driver/mysql"

	"github.com/NetwardenHQ/agent/internal/config"
)

// A password containing "@", "/" or ")" must survive the DSN intact.
func TestBuildDSN_EscapesCredentials(t *testing.T) {
	c := &Collector{config: config.DatabaseConfig{
		MySQLUser:     "mon",
		MySQLPassword: "p@ss/w)rd:x",
		MySQLHost:     "db.internal:3307",
	}}
	cfg, err := driver.ParseDSN(c.buildDSN())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "mon" || cfg.Passwd != "p@ss/w)rd:x" || cfg.Net != "tcp" || cfg.Addr != "db.internal:3307" {
		t.Fatalf("parsed back as %+v", cfg)
	}
	if cfg.TLSConfig != "preferred" {
		t.Errorf("remote host TLS = %q, want preferred", cfg.TLSConfig)
	}
}

func TestBuildDSN_LocalAndSocket(t *testing.T) {
	c := &Collector{config: config.DatabaseConfig{MySQLUser: "u", MySQLPassword: "p", MySQLSocket: "/run/mysqld/mysqld.sock"}}
	cfg, err := driver.ParseDSN(c.buildDSN())
	if err != nil || cfg.Net != "unix" || cfg.Addr != "/run/mysqld/mysqld.sock" || cfg.TLSConfig != "" {
		t.Fatalf("socket: %+v, %v", cfg, err)
	}
	c = &Collector{config: config.DatabaseConfig{}}
	cfg, err = driver.ParseDSN(c.buildDSN())
	if err != nil || cfg.Net != "tcp" || cfg.Addr != "localhost:3306" || cfg.User != "" || cfg.TLSConfig != "" {
		t.Fatalf("anonymous local: %+v, %v", cfg, err)
	}
}
