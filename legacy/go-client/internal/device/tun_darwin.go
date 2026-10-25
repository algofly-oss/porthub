//go:build darwin

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const MTU = 1380

var validName = regexp.MustCompile(`^ph[a-f0-9]{8}$`)

// Darwin allocates a fresh utun interface. Closing its descriptor removes only
// this interface and its host routes; existing VPNs and default routes stay put.
type TUN struct {
	*os.File
	Name   string
	index  int
	routes map[netip.Addr]bool
	readMu sync.Mutex
	buffer [MTU + 4]byte
}

func command(path string, args ...string) error {
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", path, err, out)
	}
	return nil
}
func Open(name string, self netip.Addr, peers []netip.Addr) (*TUN, error) {
	if !validName.MatchString(name) || !self.Is4() || !self.IsPrivate() {
		return nil, errors.New("invalid PortHub private interface")
	}
	if err := checkRoutes(append([]netip.Addr{self}, peers...), 0); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	var info unix.CtlInfo
	copy(info.Name[:], "com.apple.net.utun_control")
	if err = unix.IoctlCtlInfo(fd, &info); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err = unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	actual, err := unix.GetsockoptString(fd, 2, 2)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	t := &TUN{File: os.NewFile(uintptr(fd), actual), Name: actual, routes: map[netip.Addr]bool{}}
	fail := func(err error) (*TUN, error) { t.Close(); return nil, err }
	if err = command("/sbin/ifconfig", actual, "inet", self.String(), self.String(), "netmask", "255.255.255.255", "mtu", fmt.Sprint(MTU), "up"); err != nil {
		return fail(err)
	}
	link, err := net.InterfaceByName(actual)
	if err != nil {
		return fail(err)
	}
	t.index = link.Index
	if err = t.UpdateRoutes(peers); err != nil {
		return fail(err)
	}
	return t, nil
}
func (t *TUN) Index() int { return t.index }

// utun frames carry a four-byte, network-order address family before the IP packet.
func (t *TUN) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for {
		n, err := t.File.Read(t.buffer[:])
		if err != nil {
			return 0, err
		}
		if n < 4 || binary.BigEndian.Uint32(t.buffer[:4]) != unix.AF_INET {
			continue
		}
		if len(p) < n-4 {
			return 0, io.ErrShortBuffer
		}
		return copy(p, t.buffer[4:n]), nil
	}
}
func (t *TUN) Write(p []byte) (int, error) {
	if len(p) > MTU {
		return 0, errors.New("private packet exceeds MTU")
	}
	buf := make([]byte, len(p)+4)
	binary.BigEndian.PutUint32(buf, unix.AF_INET)
	copy(buf[4:], p)
	n, err := t.File.Write(buf)
	if n < 4 {
		return 0, err
	}
	return n - 4, err
}
func CheckRoutes(peers []netip.Addr) error { return checkRoutes(peers, 0) }
func checkRoutes(peers []netip.Addr, own int) error {
	for _, p := range peers {
		if !p.Is4() || !p.IsPrivate() {
			return errors.New("invalid private peer address")
		}
	}
	raw, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, raw)
	if err != nil {
		return err
	}
	for _, message := range messages {
		r, ok := message.(*route.RouteMessage)
		if !ok || r.Index == own {
			continue
		}
		if len(r.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		dst, ok := r.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		mask, ok := r.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if !ok {
			continue
		}
		ones, bits := net.IPMask(mask.IP[:]).Size()
		if bits != 32 || ones == 0 {
			continue
		}
		prefix := netip.PrefixFrom(netip.AddrFrom4(dst.IP), ones).Masked()
		for _, p := range peers {
			if prefix.Contains(p) {
				return fmt.Errorf("private address %s conflicts with existing route %s on interface %d", p, prefix, r.Index)
			}
		}
	}
	return nil
}
func (t *TUN) UpdateRoutes(peers []netip.Addr) error {
	wanted := map[netip.Addr]bool{}
	add := []netip.Addr{}
	for _, p := range peers {
		wanted[p] = true
		if !t.routes[p] {
			add = append(add, p)
		}
	}
	if err := checkRoutes(add, t.index); err != nil {
		return err
	}
	for _, p := range add {
		if err := command("/sbin/route", "-n", "add", "-host", p.String(), "-interface", t.Name); err != nil {
			return err
		}
		t.routes[p] = true
	}
	for p := range t.routes {
		if !wanted[p] {
			if err := command("/sbin/route", "-n", "delete", "-host", p.String(), "-interface", t.Name); err != nil {
				return err
			}
			delete(t.routes, p)
		}
	}
	return nil
}
