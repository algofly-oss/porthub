// Package policy enforces controller-issued private IPv4 policy leases.
// It never changes a public forwarding or host firewall rule.
package policy

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrPacket = errors.New("unsupported or malformed overlay packet")

type Packet struct {
	Source, Destination         netip.Addr
	Protocol                    string
	SourcePort, DestinationPort uint16
	SYN, ACK, RST, FIN          bool
	ICMPType                    uint8
	ICMPID                      uint16
}

// Parse rejects fragments rather than allowing later fragments to bypass ACLs.
// The private interface MTU prevents normal peers from fragmenting packets.
// IPv6 is not advertised until equivalent IPv6 ACL enforcement is implemented.
func Parse(b []byte) (Packet, error) {
	var p Packet
	if len(b) < 20 || b[0]>>4 != 4 {
		return p, ErrPacket
	}
	h := int(b[0]&15) * 4
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if h < 20 || h > len(b) || n != len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return p, ErrPacket
	}
	var sum uint32
	for i := 0; i < h; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		return p, ErrPacket
	}
	p.Source = netip.AddrFrom4([4]byte(b[12:16]))
	p.Destination = netip.AddrFrom4([4]byte(b[16:20]))
	switch b[9] {
	case 6:
		if n-h < 20 {
			return Packet{}, ErrPacket
		}
		tcpH := int(b[h+12]>>4) * 4
		if tcpH < 20 || tcpH > n-h {
			return Packet{}, ErrPacket
		}
		p.Protocol = "tcp"
		p.SYN = b[h+13]&2 != 0
		p.ACK = b[h+13]&16 != 0
		p.RST = b[h+13]&4 != 0
		p.FIN = b[h+13]&1 != 0
	case 17:
		if n-h < 8 || int(binary.BigEndian.Uint16(b[h+4:h+6])) != n-h {
			return Packet{}, ErrPacket
		}
		p.Protocol = "udp"
	case 1:
		if n-h < 8 {
			return Packet{}, ErrPacket
		}
		p.Protocol = "icmp"
		p.ICMPType = b[h]
		p.ICMPID = binary.BigEndian.Uint16(b[h+4 : h+6])
		// Only echo request/reply currently has well-defined connection tracking.
		if p.ICMPType != 0 && p.ICMPType != 8 {
			return Packet{}, ErrPacket
		}
	default:
		return Packet{}, ErrPacket
	}
	if p.Protocol != "icmp" {
		p.SourcePort = binary.BigEndian.Uint16(b[h : h+2])
		p.DestinationPort = binary.BigEndian.Uint16(b[h+2 : h+4])
		if p.SourcePort == 0 || p.DestinationPort == 0 {
			return Packet{}, ErrPacket
		}
	}
	return p, nil
}
