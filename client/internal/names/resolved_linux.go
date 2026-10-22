//go:build linux

package names

import (
	"errors"
	"net/netip"

	"github.com/godbus/dbus/v5"
)

// RegisterLink tells systemd-resolved to send ONLY queries under suffix to
// dns on the private interface. The link is never made a default DNS route,
// so other names, VPNs and the machine's resolvers are unaffected. resolved
// forgets the settings when the interface disappears; Unregister reverts
// them earlier on a clean shutdown.
func RegisterLink(ifindex int, dns netip.AddrPort, suffix string) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()
	manager := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	type address struct {
		Family  int32
		Address []byte
	}
	type domain struct {
		Domain      string
		RoutingOnly bool
	}
	if !dns.Addr().Is4() || dns.Port() != 53 {
		return errors.New("private DNS address must be IPv4")
	}
	calls := []struct {
		method string
		args   []any
	}{
		{"SetLinkDNS", []any{int32(ifindex), []address{{2, dns.Addr().AsSlice()}}}},
		{"SetLinkDomains", []any{int32(ifindex), []domain{{suffix, true}}}},
		{"SetLinkDefaultRoute", []any{int32(ifindex), false}},
	}
	for _, c := range calls {
		if err := manager.Call("org.freedesktop.resolve1.Manager."+c.method, 0, c.args...).Err; err != nil {
			return err
		}
	}
	return nil
}

func Unregister(ifindex int) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1").Call("org.freedesktop.resolve1.Manager.RevertLink", 0, int32(ifindex))
}
