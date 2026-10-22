package names

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func parse(t *testing.T, b []byte) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m.Header, m.Answers
}

func TestAnswersOnlyPrivateNames(t *testing.T) {
	s := &Server{}
	s.Update("ph.io", map[string]netip.Addr{"Miro.ph.io": netip.MustParseAddr("10.203.0.9"), "evil.example.com": netip.MustParseAddr("10.203.0.10")})
	h, answers := parse(t, s.Answer(query(t, "miro.PH.io.", dnsmessage.TypeA)))
	if h.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 || answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 203, 0, 9} || h.ID != 7 {
		t.Fatalf("A lookup: %v %v", h, answers)
	}
	if h, answers = parse(t, s.Answer(query(t, "miro.ph.io.", dnsmessage.TypeAAAA))); h.RCode != dnsmessage.RCodeSuccess || len(answers) != 0 {
		t.Fatal("AAAA should be NODATA")
	}
	if h, _ = parse(t, s.Answer(query(t, "unknown.ph.io.", dnsmessage.TypeA))); h.RCode != dnsmessage.RCodeNameError {
		t.Fatal("unknown private name should be NXDOMAIN")
	}
	if h, _ = parse(t, s.Answer(query(t, "evil.example.com.", dnsmessage.TypeA))); h.RCode != dnsmessage.RCodeRefused {
		t.Fatal("names outside the suffix must be refused")
	}
	if s.Answer([]byte{1, 2, 3}) != nil {
		t.Fatal("garbage answered")
	}
	// Single-label private suffix (the default).
	s.Update("phub", map[string]netip.Addr{"luna.phub": netip.MustParseAddr("10.203.0.62")})
	if h, answers = parse(t, s.Answer(query(t, "luna.phub.", dnsmessage.TypeA))); h.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatal("phub lookup failed")
	}
	if h, _ = parse(t, s.Answer(query(t, "miro.ph.io.", dnsmessage.TypeA))); h.RCode != dnsmessage.RCodeRefused {
		t.Fatal("old suffix still answered")
	}
}

func TestLoopbackResolver(t *testing.T) {
	s, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Update("phub", map[string]netip.Addr{"miro.phub": netip.MustParseAddr("10.203.0.217")})
	if !s.Address().Addr().IsLoopback() || s.Address().Port() == 0 {
		t.Fatalf("bad resolver address: %s", s.Address())
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(s.Address()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write(query(t, "miro.phub.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	h, answers := parse(t, buf[:n])
	if h.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 || answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 203, 0, 217} {
		t.Fatalf("bad loopback answer: %v", answers)
	}
}
