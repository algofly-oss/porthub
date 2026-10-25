//go:build linux

package fileserver

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

// Legacy is an lighttpd process started by the shell client's http.server.
type Legacy struct {
	PID  int
	Port int
}

var legacyConfig = regexp.MustCompile(`^/tmp/porthub-lighttpd\.[A-Za-z0-9]{6}\.conf$`)
var legacyPort = regexp.MustCompile(`(?m)^server\.port = ([0-9]+)$`)

// FindLegacy lists this user's lighttpd processes whose exact command line
// is the one the shell client used: lighttpd -D -f /tmp/porthub-lighttpd.*.conf.
// System lighttpd services and other users' processes are never matched.
func FindLegacy() []Legacy {
	var found []Legacy
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		args := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		if len(args) != 4 || filepath.Base(string(args[0])) != "lighttpd" || string(args[1]) != "-D" || string(args[2]) != "-f" || !legacyConfig.Match(args[3]) {
			continue
		}
		legacy := Legacy{PID: pid}
		if conf, err := os.ReadFile(string(args[3])); err == nil {
			if m := legacyPort.FindSubmatch(conf); m != nil {
				legacy.Port, _ = strconv.Atoi(string(m[1]))
			}
		}
		found = append(found, legacy)
	}
	return found
}

// StopLegacy sends SIGTERM, lighttpd's graceful shutdown signal.
func StopLegacy(l Legacy) error {
	return syscall.Kill(l.PID, syscall.SIGTERM)
}
