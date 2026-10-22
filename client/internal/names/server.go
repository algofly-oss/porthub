// Package names answers DNS for private peer names (alias.suffix) and nothing
// else. The OS resolver routes only the private suffix here; every other name
// keeps using the machine's normal DNS.
package names

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const ttl = 5 // seconds; peers can move or be revoked quickly

type Server struct {
	mu      sync.RWMutex
	suffix  string
	records map[string]netip.Addr
	conn    *net.UDPConn
}

func canonical(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".") + "."
}

// Listen starts answering on address (the private interface address, port 53).
func Listen(address netip.AddrPort) (*Server, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(address))
	if err != nil {
		return nil, err
	}
	s := &Server{conn: conn, records: map[string]netip.Addr{}}
	go s.serve()
	return s, nil
}

// Update replaces all records atomically. Names outside suffix are ignored.
func (s *Server) Update(suffix string, records map[string]netip.Addr) {
	suffix = canonical(suffix)
	next := make(map[string]netip.Addr, len(records))
	for name, ip := range records {
		name = canonical(name)
		if strings.HasSuffix(name, "."+suffix) && ip.Is4() {
			next[name] = ip
		}
	}
	s.mu.Lock()
	s.suffix, s.records = suffix, next
	s.mu.Unlock()
}
func (s *Server) Close() error { return s.conn.Close() }

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if reply := s.Answer(buf[:n]); reply != nil {
			_, _ = s.conn.WriteToUDPAddrPort(reply, from)
		}
	}
}

// Answer builds the response for one query packet, or nil to ignore it.
func (s *Server) Answer(query []byte) []byte {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil || header.Response {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	reply := dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionDesired: header.RecursionDesired}
	name := canonical(question.Name.String())
	s.mu.RLock()
	ip, known := s.records[name]
	inZone := s.suffix != "" && (name == s.suffix || strings.HasSuffix(name, "."+s.suffix))
	s.mu.RUnlock()
	switch {
	case header.OpCode != 0:
		reply.RCode = dnsmessage.RCodeNotImplemented
	case !inZone:
		// Not ours: never answer for names outside the private suffix.
		reply.RCode = dnsmessage.RCodeRefused
	case !known && name != s.suffix:
		reply.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), reply)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(question) != nil {
		return nil
	}
	// AAAA and other types for a known name: NOERROR with no data, so IPv6
	// lookups do not fall through to public DNS.
	if reply.RCode == dnsmessage.RCodeSuccess && known && question.Type == dnsmessage.TypeA && question.Class == dnsmessage.ClassINET {
		if b.StartAnswers() != nil {
			return nil
		}
		if b.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: ip.As4()}) != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
