package policy

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

type Peer struct {
	ID          string `json:"id"`
	IP          string `json:"ip"`
	Fingerprint string `json:"fingerprint"`
	Instance    string `json:"instance"`
	Hostname    string `json:"hostname"`
}

func (e *Engine) Revoke() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snapshot.ExpiresAt = time.Time{}
	clear(e.flows)
}

type PortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}
type Grant struct {
	Source      string      `json:"source"`
	Destination string      `json:"destination"`
	Protocol    string      `json:"protocol"`
	Ports       []PortRange `json:"ports"`
}
type Snapshot struct {
	Workspace string    `json:"workspace"`
	Revision  uint64    `json:"revision"`
	ExpiresAt time.Time `json:"expires_at"`
	Self      string    `json:"self"`
	Peers     []Peer    `json:"peers"`
	Grants    []Grant   `json:"grants"`
}
type flowKey struct {
	src, dst           netip.Addr
	protocol           string
	sport, dport, icmp uint16
}
type flow struct {
	expires time.Time
	opening Packet
	phase   uint8
}
type Engine struct {
	mu       sync.Mutex
	snapshot Snapshot
	ips      map[string]netip.Addr
	flows    map[flowKey]flow
	now      func() time.Time
}

func New() *Engine { return &Engine{now: time.Now, flows: make(map[flowKey]flow)} }

// Apply validates atomically. Failed updates revoke access, never retain an old
// allow-list. A workspace or local identity cannot change inside one process.
func (e *Engine) Apply(s Snapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	fail := func() error {
		e.snapshot.ExpiresAt = time.Time{}
		clear(e.flows)
		return errors.New("invalid or stale policy snapshot")
	}
	if s.Workspace == "" || s.Self == "" || s.Revision == 0 || !s.ExpiresAt.After(e.now()) || s.ExpiresAt.After(e.now().Add(60*time.Second)) {
		return fail()
	}
	if e.snapshot.Workspace != "" && (s.Workspace != e.snapshot.Workspace || s.Self != e.snapshot.Self || s.Revision < e.snapshot.Revision) {
		return fail()
	}
	ips := make(map[string]netip.Addr)
	unique := make(map[netip.Addr]bool)
	for _, p := range s.Peers {
		a, err := netip.ParseAddr(p.IP)
		if err != nil || !a.Is4() || !a.IsPrivate() || p.ID == "" || unique[a] || ips[p.ID].IsValid() {
			return fail()
		}
		ips[p.ID] = a
		unique[a] = true
	}
	if !ips[s.Self].IsValid() {
		return fail()
	}
	for _, g := range s.Grants {
		if !ips[g.Source].IsValid() || !ips[g.Destination].IsValid() {
			return fail()
		}
		if g.Protocol != "any" && g.Protocol != "tcp" && g.Protocol != "udp" && g.Protocol != "icmp" {
			return fail()
		}
		if len(g.Ports) > 0 && g.Protocol != "tcp" && g.Protocol != "udp" {
			return fail()
		}
		for _, p := range g.Ports {
			if p.Start == 0 || p.End < p.Start {
				return fail()
			}
		}
	}
	// Copy every mutable field: the caller cannot mutate policy after validation.
	s.Peers = append([]Peer(nil), s.Peers...)
	s.Grants = append([]Grant(nil), s.Grants...)
	for i := range s.Grants {
		s.Grants[i].Ports = append([]PortRange(nil), s.Grants[i].Ports...)
	}
	e.snapshot = s
	e.ips = ips
	// Revalidate ongoing flows on *every* update. Removing a grant immediately
	// stops replies as well, even when the established TCP connection is alive.
	for k, f := range e.flows {
		if !e.allowed(f.opening) || !f.expires.After(e.now()) {
			delete(e.flows, k)
		}
	}
	return nil
}
func (e *Engine) allowed(p Packet) bool {
	for _, g := range e.snapshot.Grants {
		if e.ips[g.Source] != p.Source || e.ips[g.Destination] != p.Destination || (g.Protocol != "any" && g.Protocol != p.Protocol) {
			continue
		}
		if len(g.Ports) == 0 {
			return true
		}
		for _, r := range g.Ports {
			if p.DestinationPort >= r.Start && p.DestinationPort <= r.End {
				return true
			}
		}
	}
	return false
}
func key(p Packet) flowKey {
	return flowKey{p.Source, p.Destination, p.Protocol, p.SourcePort, p.DestinationPort, p.ICMPID}
}
func reverse(k flowKey) flowKey { return flowKey{k.dst, k.src, k.protocol, k.dport, k.sport, k.icmp} }

// Check binds each packet to an authenticated remote peer. Neither source IP
// spoofing nor packets to a host's LAN/default gateway are accepted.
func (e *Engine) Check(b []byte, remote string, inbound bool) bool {
	p, err := Parse(b)
	if err != nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.snapshot.ExpiresAt.After(e.now()) {
		clear(e.flows)
		return false
	}
	src, dst := e.snapshot.Self, remote
	if inbound {
		src, dst = remote, e.snapshot.Self
	}
	if !e.ips[src].IsValid() || p.Source != e.ips[src] || p.Destination != e.ips[dst] {
		return false
	}
	k := key(p)
	now := e.now()
	for _, candidate := range []flowKey{k, reverse(k)} {
		f, ok := e.flows[candidate]
		if !ok || !f.expires.After(now) {
			delete(e.flows, candidate)
			continue
		}
		isReply := candidate != k
		if p.Protocol == "icmp" && ((isReply && p.ICMPType != 0) || (!isReply && p.ICMPType != 8)) {
			return false
		}
		if p.Protocol == "tcp" {
			// A reverse SYN without ACK is new initiation, not a reply.
			if isReply && p.SYN && !p.ACK {
				break
			}
			if f.phase == 0 {
				if isReply {
					if !p.SYN || !p.ACK {
						return false
					}
					f.phase = 1
				} else if !p.SYN || p.ACK {
					return false
				}
			} else if f.phase == 1 {
				if !isReply && p.ACK && !p.SYN {
					f.phase = 2
				} else if !(isReply && p.SYN && p.ACK) {
					return false
				}
			}
		}
		f.expires = now.Add(flowTTL(p.Protocol))
		e.flows[candidate] = f
		if p.RST {
			delete(e.flows, candidate)
		}
		return true
	}
	if !e.allowed(p) || (p.Protocol == "tcp" && (!p.SYN || p.ACK || p.RST || p.FIN)) || (p.Protocol == "icmp" && p.ICMPType != 8) {
		return false
	}
	if len(e.flows) >= 65536 {
		for k, f := range e.flows {
			if !f.expires.After(now) {
				delete(e.flows, k)
			}
		}
		if len(e.flows) >= 65536 {
			return false
		}
	}
	e.flows[k] = flow{expires: now.Add(flowTTL(p.Protocol)), opening: p}
	return true
}
func flowTTL(protocol string) time.Duration {
	if protocol == "tcp" {
		return 5 * time.Minute
	}
	return 30 * time.Second
}
