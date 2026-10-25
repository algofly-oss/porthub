package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func packet(src, dst string, proto byte, sport, dport uint16, flags byte) []byte {
	n := 40
	if proto == 17 || proto == 1 {
		n = 28
	}
	b := make([]byte, n)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	b[8] = 64
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	if proto == 6 {
		b[32] = 0x50
		b[33] = flags
	}
	if proto == 17 {
		binary.BigEndian.PutUint16(b[24:26], 8)
	}
	if proto == 1 {
		b[20] = flags
		binary.BigEndian.PutUint16(b[24:26], sport)
	}
	checksum(b)
	return b
}
func checksum(b []byte) {
	b[10] = 0
	b[11] = 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:12], ^uint16(sum))
}
func snapshot() Snapshot {
	return Snapshot{Workspace: "workspace-a", Self: "a", Revision: 1, ExpiresAt: time.Now().Add(15 * time.Second), Peers: []Peer{{ID: "a", IP: "10.203.0.1"}, {ID: "b", IP: "10.203.0.2"}}, Grants: []Grant{{Source: "a", Destination: "b", Protocol: "tcp", Ports: []PortRange{{22, 22}}}}}
}
func TestDirectionalTCPAndImmediateRevocation(t *testing.T) {
	e := New()
	s := snapshot()
	if err := e.Apply(s); err != nil {
		t.Fatal(err)
	}
	syn := packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 2)
	if !e.Check(syn, "b", false) {
		t.Fatal("allowed SYN denied")
	}
	if e.Check(packet("10.203.0.2", "10.203.0.1", 6, 22, 40000, 2), "b", true) {
		t.Fatal("reverse initiation allowed")
	}
	if !e.Check(packet("10.203.0.2", "10.203.0.1", 6, 22, 40000, 18), "b", true) {
		t.Fatal("SYN ACK denied")
	}
	if !e.Check(packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 16), "b", false) {
		t.Fatal("ACK denied")
	}
	if !e.Check(packet("10.203.0.2", "10.203.0.1", 6, 22, 40000, 16), "b", true) {
		t.Fatal("established reply denied")
	}
	s.Revision++
	s.Grants = nil
	if err := e.Apply(s); err != nil {
		t.Fatal(err)
	}
	if e.Check(syn, "b", false) || e.Check(packet("10.203.0.2", "10.203.0.1", 6, 22, 40000, 16), "b", true) {
		t.Fatal("revocation retained an established flow")
	}
}
func TestDenySpoofFragmentsAndNoPolicy(t *testing.T) {
	e := New()
	s := snapshot()
	s.Grants = nil
	_ = e.Apply(s)
	if e.Check(packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 2), "b", false) {
		t.Fatal("default deny bypassed")
	}
	s.Grants = snapshot().Grants
	_ = e.Apply(s)
	for _, b := range [][]byte{packet("10.203.0.9", "10.203.0.2", 6, 40000, 22, 2), packet("10.203.0.1", "192.168.1.1", 6, 40000, 22, 2), packet("10.203.0.1", "10.203.0.2", 6, 40000, 23, 2), packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 16), {}} {
		if e.Check(b, "b", false) {
			t.Fatal("invalid packet accepted")
		}
	}
	b := packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 2)
	b[6] = 0x20
	checksum(b)
	if e.Check(b, "b", false) {
		t.Fatal("fragment accepted")
	}
	b[6] = 0
	checksum(b)
	b[12] ^= 1
	if e.Check(b, "b", false) {
		t.Fatal("bad IP checksum accepted")
	}
	if e.Check(packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 2), "other-tenant", false) {
		t.Fatal("unknown peer accepted")
	}
}
func TestExpiredLeaseInvalidSnapshotAndCopies(t *testing.T) {
	e := New()
	now := time.Now()
	e.now = func() time.Time { return now }
	s := snapshot()
	_ = e.Apply(s)
	s.Grants[0].Ports[0].End = 65535
	if e.Check(packet("10.203.0.1", "10.203.0.2", 6, 40000, 80, 2), "b", false) {
		t.Fatal("caller mutated policy")
	}
	now = now.Add(time.Minute)
	if e.Check(packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 2), "b", false) {
		t.Fatal("expired lease allowed")
	}
	now = time.Now()
	s = snapshot()
	s.Revision = 2
	_ = e.Apply(s)
	s.Revision = 1
	if e.Apply(s) == nil {
		t.Fatal("rollback accepted")
	}
	if e.Check(packet("10.203.0.1", "10.203.0.2", 6, 40000, 22, 2), "b", false) {
		t.Fatal("invalid update kept old grants")
	}
}
func TestUDPAndICMPReplies(t *testing.T) {
	for _, proto := range []byte{17, 1} {
		e := New()
		s := snapshot()
		s.Grants[0].Protocol = "udp"
		s.Grants[0].Ports = nil
		if proto == 1 {
			s.Grants[0].Protocol = "icmp"
		}
		_ = e.Apply(s)
		flags := byte(0)
		if proto == 1 {
			flags = 8
		}
		if !e.Check(packet("10.203.0.1", "10.203.0.2", proto, 1234, 53, flags), "b", false) {
			t.Fatal("initiation denied")
		}
		port, other := uint16(53), uint16(1234)
		if proto == 1 {
			port = 1234
			other = 0
		}
		if !e.Check(packet("10.203.0.2", "10.203.0.1", proto, port, other, 0), "b", true) {
			t.Fatal("reply denied")
		}
	}
}
func FuzzParse(f *testing.F) {
	f.Add(packet("10.203.0.1", "10.203.0.2", 6, 1234, 22, 2))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}
