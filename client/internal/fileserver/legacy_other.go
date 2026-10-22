//go:build !linux

package fileserver

import "errors"

type Legacy struct {
	PID  int
	Port int
}

// Legacy detection relies on /proc; elsewhere nothing is matched.
func FindLegacy() []Legacy { return nil }

func StopLegacy(Legacy) error { return errors.New("not supported on this OS") }
