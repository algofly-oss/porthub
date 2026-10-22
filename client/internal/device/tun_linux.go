//go:build linux

package device

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TUN is configured entirely through netlink from inside this binary; no `ip`
// command, Docker or other external tool is required on the host.
type TUN struct {
	*os.File
	Name   string
	link   netlink.Link
	routes map[netip.Addr]bool
}

var validName = regexp.MustCompile(`^ph[a-f0-9]{8}$`)

// MTU of the private interface; equals mesh.MaxPacket (checked in agent tests).
const MTU = 1380

// Open owns a non-persistent interface. Closing it removes only this process's
// interface and routes. Existing interfaces are never adopted or overwritten.
func Open(name string, self netip.Addr, peers []netip.Addr) (*TUN, error) {
	if !validName.MatchString(name) || !self.Is4() || !self.IsPrivate() {
		return nil, errors.New("invalid PortHub private interface")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, errors.New("private interface already exists; refusing to alter it")
	}
	if err := CheckRoutes(append([]netip.Addr{self}, peers...)); err != nil {
		return nil, err
	}
	// The descriptor is attached before os.NewFile wraps it: a file registered
	// with Go's poller before TUNSETIFF reports "not pollable" on every read.
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}
	device := &TUN{File: os.NewFile(uintptr(fd), "/dev/net/tun"), Name: name, routes: map[netip.Addr]bool{}}
	fail := func(step string, err error) (*TUN, error) {
		device.Close()
		return nil, fmt.Errorf("configure private interface (%s): %w", step, err)
	}
	if device.link, err = netlink.LinkByName(name); err != nil {
		return fail("find", err)
	}
	if err = netlink.AddrAdd(device.link, &netlink.Addr{IPNet: hostNet(self)}); err != nil {
		return fail("address", err)
	}
	if err = netlink.LinkSetMTU(device.link, MTU); err != nil {
		return fail("mtu", err)
	}
	if err = netlink.LinkSetUp(device.link); err != nil {
		return fail("up", err)
	}
	for _, peer := range peers {
		if peer == self {
			continue
		}
		if err = device.addRoute(peer); err != nil {
			return fail("route", err)
		}
	}
	return device, nil
}

// Index is the kernel interface index (used for per-link DNS registration).
func (t *TUN) Index() int { return t.link.Attrs().Index }

func hostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(32, 32)}
}
func (t *TUN) route(peer netip.Addr) *netlink.Route {
	return &netlink.Route{LinkIndex: t.link.Attrs().Index, Dst: hostNet(peer), Scope: netlink.SCOPE_LINK}
}

// addRoute uses RouteAdd (NLM_F_EXCL), never RouteReplace: an existing route
// owned by anything else makes the call fail instead of being overwritten.
func (t *TUN) addRoute(peer netip.Addr) error {
	if err := netlink.RouteAdd(t.route(peer)); err != nil {
		return fmt.Errorf("add private route %s: %w", peer, err)
	}
	t.routes[peer] = true
	return nil
}

func (t *TUN) UpdateRoutes(peers []netip.Addr) error {
	wanted := make(map[netip.Addr]bool)
	var additions []netip.Addr
	for _, peer := range peers {
		wanted[peer] = true
		if !t.routes[peer] {
			additions = append(additions, peer)
		}
	}
	if err := CheckRoutes(additions); err != nil {
		return err
	}
	for _, peer := range additions {
		if err := t.addRoute(peer); err != nil {
			return err
		}
	}
	for peer := range t.routes {
		if !wanted[peer] {
			if err := netlink.RouteDel(t.route(peer)); err != nil {
				return fmt.Errorf("remove private route %s: %w", peer, err)
			}
			delete(t.routes, peer)
		}
	}
	return nil
}

type route struct {
	dst netip.Prefix
	dev string
}

// CheckRoutes refuses addresses already covered by any IPv4 route in any table
// (other VPNs, LANs, Docker networks). Default routes are ignored.
func CheckRoutes(peers []netip.Addr) error {
	if len(peers) == 0 {
		return nil
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("read routing tables: %w", err)
	}
	names := map[int]string{}
	var routes []route
	for _, r := range list {
		if r.Dst == nil {
			continue
		}
		ones, _ := r.Dst.Mask.Size()
		a, ok := netip.AddrFromSlice(r.Dst.IP)
		if !ok {
			return fmt.Errorf("cannot validate existing route %v", r.Dst)
		}
		if ones == 0 {
			continue
		}
		if _, ok := names[r.LinkIndex]; !ok {
			names[r.LinkIndex] = fmt.Sprint(r.LinkIndex)
			if link, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
				names[r.LinkIndex] = link.Attrs().Name
			}
		}
		routes = append(routes, route{netip.PrefixFrom(a.Unmap(), ones), names[r.LinkIndex]})
	}
	return checkRoutes(routes, peers)
}
func checkRoutes(routes []route, peers []netip.Addr) error {
	for _, peer := range peers {
		if !peer.Is4() || !peer.IsPrivate() {
			return errors.New("invalid private peer address")
		}
	}
	for _, r := range routes {
		if !r.dst.IsValid() || r.dst.Bits() == 0 {
			continue
		}
		for _, peer := range peers {
			if r.dst.Contains(peer) {
				return fmt.Errorf("private address %s conflicts with existing route %s via %s", peer, r.dst, r.dev)
			}
		}
	}
	return nil
}
