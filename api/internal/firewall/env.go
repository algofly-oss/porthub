// Package firewall is the Go port of the Python firewall service
// (firewall/): nftables port policies, per-port traffic sampling and the
// SQLite state, served over the same HTTP API.
package firewall

import (
	"fmt"
	"os"
	"strings"
)

// Config mirrors firewall/shared/env.py.
type Config struct {
	APIRoot              string // FW_API_ROOT, default /api
	APIKey               string // FW_API_KEY, required
	DBPath               string // FW_DB_PATH, default /state/firewall.db
	BufferSeconds        int64  // FW_BUFFER_SECONDS, default 300
	ActiveTTL            int64  // FW_ACTIVE_TTL, default 300
	RecentIPTTL          int64  // FW_RECENT_IP_TTL, default 300
	RecentIPHistoryLimit int64  // FW_RECENT_IP_HISTORY_LIMIT, default 10
	NFTTable             string // FW_NFT_TABLE, default "inet rathole"
	Host                 string // FW_HOST, default 0.0.0.0
	Port                 int64  // FW_PORT, default 8001
}

// LoadConfig reads the environment exactly like env.py.
func LoadConfig() (Config, error) {
	c := Config{
		APIRoot:  strings.TrimRight(getenv("FW_API_ROOT", "/api"), "/"),
		DBPath:   getenv("FW_DB_PATH", "/state/firewall.db"),
		NFTTable: getenv("FW_NFT_TABLE", "inet rathole"),
		Host:     getenv("FW_HOST", "0.0.0.0"),
	}
	if c.APIRoot == "" {
		c.APIRoot = "/api"
	}
	c.APIKey = strings.TrimSpace(os.Getenv("FW_API_KEY"))
	if c.APIKey == "" {
		return c, fmt.Errorf("Missing FW_API_KEY")
	}
	for _, v := range []struct {
		name string
		def  int64
		dst  *int64
	}{
		{"FW_BUFFER_SECONDS", 300, &c.BufferSeconds},
		{"FW_ACTIVE_TTL", 300, &c.ActiveTTL},
		{"FW_RECENT_IP_TTL", 300, &c.RecentIPTTL},
		{"FW_RECENT_IP_HISTORY_LIMIT", 10, &c.RecentIPHistoryLimit},
		{"FW_PORT", 8001, &c.Port},
	} {
		s := strings.TrimSpace(os.Getenv(v.name))
		if s == "" {
			*v.dst = v.def
			continue
		}
		n, ok, _ := pyIntString(s)
		if !ok {
			return c, fmt.Errorf("%s must be an integer", v.name)
		}
		*v.dst = n
	}
	return c, nil
}

// getenv is os.getenv(name, default): set-but-empty stays empty.
func getenv(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}
