//go:build !linux && !darwin

package names

import (
	"errors"
	"net/netip"
)

func RegisterLink(int, netip.AddrPort, string) error {
	return errors.New("private names are not supported on this OS yet")
}
func Unregister(int) {}
