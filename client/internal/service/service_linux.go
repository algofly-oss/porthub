//go:build linux

// Package service installs the private-network agent as a boot-time system
// service. systemd is driven over its D-Bus API, so no systemctl or other
// command-line tool is needed.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/godbus/dbus/v5"
)

const (
	Unit        = "porthub-private.service"
	unitPath    = "/etc/systemd/system/" + Unit
	binaryPath  = "/opt/porthub/bin/porthub" // separate from the legacy shell client
	profilePath = "/etc/porthub/private.json"
)

func unitFile() string {
	return fmt.Sprintf(`# Managed by PortHub (porthub service install).
[Unit]
Description=PortHub private network agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run --profile %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, binaryPath, profilePath)
}

func manager() (dbus.BusObject, func(), error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, nil, fmt.Errorf("systemd is required: %w", err)
	}
	return conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1"), func() { conn.Close() }, nil
}

func call(m dbus.BusObject, method string, args ...any) error {
	return m.Call("org.freedesktop.systemd1.Manager."+method, 0, args...).Err
}

// Install copies the running binary and the profile into system locations,
// writes the unit and enables and (re)starts it.
func Install(profile string) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo) to install the service")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self != binaryPath {
		if err = copyFile(self, binaryPath, 0755); err != nil {
			return fmt.Errorf("install binary: %w", err)
		}
	}
	if abs, _ := filepath.Abs(profile); abs != profilePath {
		if err = copyFile(profile, profilePath, 0600); err != nil {
			return fmt.Errorf("install profile: %w", err)
		}
	}
	if err = os.WriteFile(unitPath, []byte(unitFile()), 0644); err != nil {
		return err
	}
	m, done, err := manager()
	if err != nil {
		return err
	}
	defer done()
	if err = call(m, "Reload"); err != nil {
		return err
	}
	if err = call(m, "EnableUnitFiles", []string{Unit}, false, true); err != nil {
		return fmt.Errorf("enable at boot: %w", err)
	}
	if err = call(m, "RestartUnit", Unit, "replace"); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	return nil
}

// Uninstall stops and disables the service and removes its unit. The profile
// is kept unless purge is set, so a reinstall keeps the same identity.
func Uninstall(purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo) to remove the service")
	}
	m, done, err := manager()
	if err != nil {
		return err
	}
	defer done()
	_ = call(m, "StopUnit", Unit, "replace")
	_ = call(m, "DisableUnitFiles", []string{Unit}, false)
	if err = os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = call(m, "Reload")
	if purge {
		_ = os.Remove(profilePath)
		_ = os.Remove(binaryPath)
	}
	return nil
}

// Status reports systemd's view of the service.
func Status() (active, enabled string, err error) {
	m, done, err := manager()
	if err != nil {
		return "", "", err
	}
	defer done()
	var state string
	if err = m.Call("org.freedesktop.systemd1.Manager.GetUnitFileState", 0, Unit).Store(&state); err != nil {
		return "not installed", "", nil
	}
	var path dbus.ObjectPath
	if err = m.Call("org.freedesktop.systemd1.Manager.LoadUnit", 0, Unit).Store(&path); err != nil {
		return "unknown", state, nil
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return "unknown", state, nil
	}
	defer conn.Close()
	v, err := conn.Object("org.freedesktop.systemd1", path).GetProperty("org.freedesktop.systemd1.Unit.ActiveState")
	if err != nil {
		return "unknown", state, nil
	}
	return v.Value().(string), state, nil
}
