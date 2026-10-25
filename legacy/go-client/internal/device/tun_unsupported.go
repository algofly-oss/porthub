//go:build !linux && !darwin

package device

import (
	"errors"
	"net/netip"
	"os"
)

const MTU = 1380

type TUN struct {
	*os.File
	Name string
}

func Open(string, netip.Addr, []netip.Addr) (*TUN, error) {
	return nil, errors.New("native private interface not implemented on this OS yet")
}
func (t *TUN) UpdateRoutes([]netip.Addr) error {
	return errors.New("native private interface not implemented on this OS yet")
}
