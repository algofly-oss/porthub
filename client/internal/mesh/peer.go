// Package mesh carries private IP packets between two machines.
//
// ICE (pion/ice) finds the best working path: same LAN, direct across NATs,
// or the gateway relay. Each IP packet then travels as one DTLS record
// (AES-GCM) on that path. There is no message layer in between: the TCP and
// UDP flows inside the tunnel bring their own reliability and congestion
// control, so the tunnel adds as little latency and overhead as possible.
//
// Both ends pin each other's certificate fingerprint as authenticated by the
// PortHub control plane; encryption is end-to-end even through the relay.
package mesh

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"golang.org/x/net/proxy"
)

// MaxPacket is the largest IP packet carried (the private interface MTU).
// With DTLS (37 bytes) and IP/UDP (28) it stays under a 1500-byte path, also
// with PPPoE.
const MaxPacket = 1380

const (
	sendQueue      = 2048 // packets buffered per peer before dropping
	transportLabel = "a=porthub-transport:dtls1"
)

var ErrNotReady = errors.New("private peer is not connected")

var privateInterface = regexp.MustCompile(`^ph[a-f0-9]{8}$`)

// Container and VM bridges only reach this host's own guests: never useful
// to another machine, and each one slows candidate gathering.
var hostOnlyInterface = regexp.MustCompile(`^(docker\d*|br-[0-9a-f]+|veth.*|virbr\d*|cni\d*|flannel.*|cali.*|lxcbr\d*|lxdbr\d*)$`)

// ICEServer is a STUN/TURN server as sent by the control plane.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Description is the offer or answer exchanged through the control plane.
type Description struct {
	Type string `json:"type"` // "offer" or "answer"
	SDP  string `json:"sdp"`
}

// Cert is this machine's DTLS identity for one agent run.
type Cert struct {
	tls         tls.Certificate
	fingerprint string
}

func Certificate() (*Cert, error) {
	c, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	return &Cert{tls: c, fingerprint: fingerprintOf(c.Certificate[0])}, nil
}

func Fingerprint(c *Cert) (string, error) {
	if c == nil {
		return "", errors.New("missing certificate")
	}
	return c.fingerprint, nil
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

type config struct {
	dialer    proxy.Dialer
	relayOnly bool
}

// Option adjusts how a peer reaches its peer.
type Option func(*config)

// WithRelay sends TURN-over-TCP connections through d (the gateway relay).
func WithRelay(d proxy.Dialer) Option { return func(c *config) { c.dialer = d } }

// RelayOnly forces the relay path (used to test and to measure it).
func RelayOnly() Option { return func(c *config) { c.relayOnly = true } }

type Peer struct {
	agent    *ice.Agent
	cert     *Cert
	onPacket func([]byte)
	ctx      context.Context
	cancel   context.CancelFunc

	mu         sync.Mutex
	conn       *dtls.Conn
	path       string
	candidates []string
	gathered   chan struct{}
	started    bool

	ready, done         chan struct{}
	readyOnce, doneOnce sync.Once
	queue               chan []byte
}

func New(cert *Cert, servers []ICEServer, loopback bool, onPacket func([]byte), options ...Option) (*Peer, error) {
	if cert == nil || onPacket == nil {
		return nil, errors.New("certificate and packet receiver required")
	}
	var cfg config
	for _, option := range options {
		option(&cfg)
	}
	var urls []*stun.URI
	for _, server := range servers {
		for _, raw := range server.URLs {
			u, err := stun.ParseURI(raw)
			if err != nil {
				continue
			}
			u.Username, u.Password = server.Username, server.Credential
			urls = append(urls, u)
		}
	}
	types := []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypePeerReflexive, ice.CandidateTypeRelay}
	if cfg.relayOnly {
		types = []ice.CandidateType{ice.CandidateTypeRelay}
	}
	agentOptions := []ice.AgentOption{
		ice.WithUrls(urls),
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeTCP4}),
		ice.WithCandidateTypes(types),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled),
		ice.WithInterfaceFilter(func(name string) bool {
			return !privateInterface.MatchString(name) && !hostOnlyInterface.MatchString(name)
		}),
		ice.WithDisconnectedTimeout(5 * time.Second),
		ice.WithFailedTimeout(12 * time.Second),
		ice.WithKeepaliveInterval(2 * time.Second),
	}
	if cfg.dialer != nil {
		agentOptions = append(agentOptions, ice.WithProxyDialer(cfg.dialer))
	}
	if loopback {
		agentOptions = append(agentOptions, ice.WithIncludeLoopback())
	}
	agent, err := ice.NewAgentWithOptions(agentOptions...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Peer{agent: agent, cert: cert, onPacket: onPacket, ctx: ctx, cancel: cancel,
		gathered: make(chan struct{}), ready: make(chan struct{}), done: make(chan struct{}), queue: make(chan []byte, sendQueue)}
	_ = agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			p.mu.Lock()
			defer p.mu.Unlock()
			select {
			case <-p.gathered:
			default:
				close(p.gathered)
			}
			return
		}
		p.mu.Lock()
		p.candidates = append(p.candidates, c.Marshal())
		p.mu.Unlock()
	})
	_ = agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		path := "direct"
		if local.Type() == ice.CandidateTypeRelay || remote.Type() == ice.CandidateTypeRelay {
			path = "relay"
		}
		p.mu.Lock()
		p.path = path
		p.mu.Unlock()
	})
	_ = agent.OnConnectionStateChange(func(s ice.ConnectionState) {
		if s == ice.ConnectionStateFailed || s == ice.ConnectionStateClosed {
			p.finish()
		}
	})
	return p, nil
}

func (p *Peer) finish() { p.doneOnce.Do(func() { close(p.done) }) }

// describe gathers local candidates and renders them as SDP-style text. The
// fingerprint line is what the control plane verifies against the enrolled
// identity; the transport line lets older clients be told apart.
func (p *Peer) describe(ctx context.Context, kind string) (Description, error) {
	if err := p.agent.GatherCandidates(); err != nil {
		return Description{}, err
	}
	select {
	case <-p.gathered:
	case <-ctx.Done():
		return Description{}, ctx.Err()
	}
	ufrag, pwd, err := p.agent.GetLocalUserCredentials()
	if err != nil {
		return Description{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=porthub\r\nt=0 0\r\n%s\r\n", transportLabel)
	fmt.Fprintf(&b, "a=ice-ufrag:%s\r\na=ice-pwd:%s\r\na=fingerprint:sha-256 %s\r\n", ufrag, pwd, p.cert.fingerprint)
	p.mu.Lock()
	for _, c := range p.candidates {
		fmt.Fprintf(&b, "a=candidate:%s\r\n", c)
	}
	p.mu.Unlock()
	return Description{Type: kind, SDP: b.String()}, nil
}

type remoteInfo struct{ ufrag, pwd string }

// apply verifies the remote description against the pinned fingerprint and
// hands its candidates to ICE.
func (p *Peer) apply(d Description, pin string) (remoteInfo, error) {
	var info remoteInfo
	if len(d.SDP) > 65536 || len(pin) != 95 {
		return info, errors.New("invalid pinned peer identity")
	}
	found, transport := false, false
	var candidates []string
	scanner := bufio.NewScanner(strings.NewReader(d.SDP))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == transportLabel:
			transport = true
		case strings.HasPrefix(line, "a=fingerprint:"):
			parts := strings.Fields(strings.TrimPrefix(line, "a=fingerprint:"))
			if len(parts) != 2 || parts[0] != "sha-256" || !strings.EqualFold(parts[1], pin) {
				return info, errors.New("peer certificate fingerprint mismatch")
			}
			found = true
		case strings.HasPrefix(line, "a=ice-ufrag:"):
			info.ufrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		case strings.HasPrefix(line, "a=ice-pwd:"):
			info.pwd = strings.TrimPrefix(line, "a=ice-pwd:")
		case strings.HasPrefix(line, "a=candidate:"):
			candidates = append(candidates, strings.TrimPrefix(line, "a=candidate:"))
		}
	}
	if !found {
		return info, errors.New("missing peer certificate fingerprint")
	}
	if !transport {
		return info, errors.New("peer runs an older PortHub client; update it to connect")
	}
	if info.ufrag == "" || info.pwd == "" {
		return info, errors.New("missing ICE credentials")
	}
	for _, raw := range candidates {
		c, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			continue
		}
		_ = p.agent.AddRemoteCandidate(c)
	}
	return info, nil
}

func (p *Peer) Offer(ctx context.Context) (Description, error) {
	return p.describe(ctx, "offer")
}

// Answer accepts the offer and starts connecting as the ICE-controlled side
// and DTLS server.
func (p *Peer) Answer(ctx context.Context, offer Description, pin string) (Description, error) {
	if offer.Type != "offer" {
		return Description{}, errors.New("offer required")
	}
	info, err := p.apply(offer, pin)
	if err != nil {
		return Description{}, err
	}
	answer, err := p.describe(ctx, "answer")
	if err != nil {
		return Description{}, err
	}
	p.start(false, info, pin)
	return answer, nil
}

// Remote applies the answer and starts connecting as the ICE-controlling
// side and DTLS client.
func (p *Peer) Remote(d Description, pin string) error {
	if d.Type != "answer" {
		return errors.New("answer required")
	}
	info, err := p.apply(d, pin)
	if err != nil {
		return err
	}
	p.start(true, info, pin)
	return nil
}

func (p *Peer) start(controlling bool, remote remoteInfo, pin string) {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(p.ctx, 40*time.Second)
		defer cancel()
		var ic *ice.Conn
		var err error
		if controlling {
			ic, err = p.agent.Dial(ctx, remote.ufrag, remote.pwd)
		} else {
			ic, err = p.agent.Accept(ctx, remote.ufrag, remote.pwd)
		}
		if err != nil {
			p.finish()
			return
		}
		verify := func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !strings.EqualFold(fingerprintOf(raw[0]), pin) {
				return errors.New("peer certificate does not match the enrolled identity")
			}
			return nil
		}
		cfg := &dtls.Config{
			Certificates:          []tls.Certificate{p.cert.tls},
			CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
			VerifyPeerCertificate: verify,
			// The pin above is the trust anchor; there is no CA chain.
			InsecureSkipVerify: true,
			MTU:                1450,
		}
		packetConn := dtlsnet.PacketConnFromConn(ic)
		var conn *dtls.Conn
		if controlling {
			conn, err = dtls.Client(packetConn, ic.RemoteAddr(), cfg)
		} else {
			cfg.ClientAuth = dtls.RequireAnyClientCert
			conn, err = dtls.Server(packetConn, ic.RemoteAddr(), cfg)
		}
		if err == nil {
			err = conn.HandshakeContext(ctx)
		}
		if err != nil {
			p.finish()
			return
		}
		p.mu.Lock()
		p.conn = conn
		p.mu.Unlock()
		p.readyOnce.Do(func() { close(p.ready) })
		go p.writeLoop(conn)
		p.readLoop(conn)
	}()
}

func (p *Peer) readLoop(conn *dtls.Conn) {
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			p.finish()
			return
		}
		if n >= 20 && n <= MaxPacket {
			p.onPacket(buf[:n])
		}
	}
}

// writeLoop decouples senders from a slow path (e.g. relay over TCP), so one
// peer never stalls the packets of others.
func (p *Peer) writeLoop(conn *dtls.Conn) {
	for {
		select {
		case <-p.done:
			return
		case b := <-p.queue:
			if _, err := conn.Write(b); err != nil {
				p.finish()
				return
			}
		}
	}
}

func (p *Peer) Ready() bool {
	select {
	case <-p.done:
		return false
	case <-p.ready:
		return true
	default:
		return false
	}
}

func (p *Peer) Failed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *Peer) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return ErrNotReady
	case <-p.ready:
		return nil
	}
}

func (p *Peer) Send(b []byte) error {
	if len(b) < 20 || len(b) > MaxPacket {
		return errors.New("invalid private IP packet size")
	}
	if !p.Ready() {
		return ErrNotReady
	}
	select {
	case p.queue <- append([]byte(nil), b...):
		return nil
	default:
		return errors.New("private peer congested")
	}
}

func (p *Peer) Close() error {
	p.finish()
	p.cancel()
	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return p.agent.Close()
}

func (p *Peer) Path() (string, error) {
	if !p.Ready() {
		return "", ErrNotReady
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path == "" {
		return "", ErrNotReady
	}
	return p.path, nil
}
