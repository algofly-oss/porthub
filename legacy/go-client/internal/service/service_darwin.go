//go:build darwin

package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	Unit          = "com.porthub.private"
	unitPath      = "/Library/LaunchDaemons/" + Unit + ".plist"
	binaryPath    = "/usr/local/libexec/porthub/porthub"
	profilePath   = "/usr/local/etc/porthub/private.json"
	serviceMarker = "<!-- Managed by PortHub private network -->"
)

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func unitFile() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
%s
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>run</string><string>--profile</string><string>%s</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>StandardOutPath</key><string>/usr/local/var/log/porthub/private.log</string>
<key>StandardErrorPath</key><string>/usr/local/var/log/porthub/private.log</string>
</dict></plist>
`, serviceMarker, Unit, xmlText(binaryPath), xmlText(profilePath))
}
func launch(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", args[0], err, out)
	}
	return nil
}
func ownedUnit() error {
	info, err := os.Lstat(unitPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("private service path is not a regular file")
	}
	b, err := os.ReadFile(unitPath)
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte(serviceMarker)) {
		return errors.New("private service file already exists and is not managed by PortHub")
	}
	return nil
}
func Install(profile string) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo) to install the service")
	}
	if err := ownedUnit(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	if self != binaryPath {
		if err = copyFile(self, binaryPath, 0755); err != nil {
			return err
		}
	}
	if abs, _ := filepath.Abs(profile); abs != profilePath {
		if err = copyFile(profile, profilePath, 0600); err != nil {
			return err
		}
	}
	if err = os.MkdirAll("/usr/local/var/log/porthub", 0755); err != nil {
		return err
	}
	if err = os.WriteFile(unitPath, []byte(unitFile()), 0644); err != nil {
		return err
	}
	_ = launch("bootout", "system/"+Unit)
	if err = launch("enable", "system/"+Unit); err != nil {
		return err
	}
	if err = launch("bootstrap", "system", unitPath); err != nil {
		return err
	}
	return launch("kickstart", "-k", "system/"+Unit)
}
func Uninstall(purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo) to remove the service")
	}
	if err := ownedUnit(); err != nil {
		return err
	}
	_ = launch("bootout", "system/"+Unit)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if purge {
		_ = os.Remove(profilePath)
		_ = os.Remove(binaryPath)
	}
	return nil
}
func Status() (string, string, error) {
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return "not installed", "", nil
	} else if err != nil {
		return "", "", err
	}
	out, err := exec.Command("/bin/launchctl", "print", "system/"+Unit).Output()
	if err != nil {
		return "stopped", "enabled", nil
	}
	state := "stopped"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "state = running" {
			state = "running"
			break
		}
	}
	return state, "enabled", nil
}
