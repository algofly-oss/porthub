// Package mesh carries private IP packets over ICE + DTLS data channels.
// The controller authenticates the SDP fingerprint; encryption is end-to-end,
// including when ICE selects a TURN relay. No public service ports are opened.
package mesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

const MaxPacket = 1200

var privateInterface = regexp.MustCompile(`^ph[a-f0-9]{8}$`)

var ErrNotReady = errors.New("private peer is not connected")

func (p *Peer) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dc != nil && p.dc.ReadyState() == webrtc.DataChannelStateOpen
}
func (p *Peer) Failed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

type Peer struct {
	pc       *webrtc.PeerConnection
	mu       sync.RWMutex
	dc       *webrtc.DataChannel
	path     string
	ready    chan struct{}
	done     chan struct{}
	stop     sync.Once
	onPacket func([]byte)
}

func Certificate() (*webrtc.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return webrtc.GenerateCertificate(key)
}
func Fingerprint(c *webrtc.Certificate) (string, error) {
	fs, err := c.GetFingerprints()
	if err != nil {
		return "", err
	}
	for _, f := range fs {
		if f.Algorithm == "sha-256" {
			return strings.ToUpper(f.Value), nil
		}
	}
	return "", errors.New("SHA-256 certificate fingerprint missing")
}

func New(cert *webrtc.Certificate, servers []webrtc.ICEServer, loopback bool, onPacket func([]byte)) (*Peer, error) {
	if cert == nil || onPacket == nil {
		return nil, errors.New("certificate and packet receiver required")
	}
	settings := webrtc.SettingEngine{}
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeTCP4})
	settings.SetIncludeLoopbackCandidate(loopback)
	// Never gather candidates on PortHub's own private interfaces: a peer
	// connection carried inside the overlay it provides would recurse.
	settings.SetInterfaceFilter(func(name string) bool { return !privateInterface.MatchString(name) })
	settings.SetICETimeouts(5*time.Second, 12*time.Second, 2*time.Second)
	settings.SetSCTPMaxMessageSize(MaxPacket)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: servers, Certificates: []webrtc.Certificate{*cert}})
	if err != nil {
		return nil, err
	}
	p := &Peer{pc: pc, ready: make(chan struct{}), done: make(chan struct{}), onPacket: onPacket}
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateClosed || s == webrtc.PeerConnectionStateFailed {
			p.stop.Do(func() { close(p.done) })
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) { p.attach(dc) })
	// Polling ICETransport.GetSelectedCandidatePair races with ICE start-up
	// inside Pion, so the selected path is recorded from its own callback.
	pc.SCTP().Transport().ICETransport().OnSelectedCandidatePairChange(func(pair *webrtc.ICECandidatePair) {
		path := "direct"
		if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
			path = "relay"
		}
		p.mu.Lock()
		p.path = path
		p.mu.Unlock()
	})
	return p, nil
}
func (p *Peer) attach(dc *webrtc.DataChannel) {
	// Unordered, so one lost packet never stalls the others. Retransmission
	// is allowed: on lossy internet paths a retransmitted packet looks like
	// delay to the TCP flows inside instead of loss, which keeps them fast.
	if dc.Label() != "porthub-ip-v1" || dc.Ordered() {
		_ = dc.Close()
		return
	}
	dc.OnOpen(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.dc != nil {
			_ = dc.Close()
			return
		}
		p.dc = dc
		close(p.ready)
	})
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if !m.IsString && len(m.Data) >= 20 && len(m.Data) <= MaxPacket {
			p.onPacket(m.Data)
		}
	})
}
func (p *Peer) description(ctx context.Context, offer bool) (webrtc.SessionDescription, error) {
	var s webrtc.SessionDescription
	var err error
	if offer {
		ordered := false
		dc, e := p.pc.CreateDataChannel("porthub-ip-v1", &webrtc.DataChannelInit{Ordered: &ordered})
		if e != nil {
			return s, e
		}
		p.attach(dc)
		s, err = p.pc.CreateOffer(nil)
	} else {
		s, err = p.pc.CreateAnswer(nil)
	}
	if err != nil {
		return s, err
	}
	done := webrtc.GatheringCompletePromise(p.pc)
	if err = p.pc.SetLocalDescription(s); err != nil {
		return s, err
	}
	select {
	case <-ctx.Done():
		return s, ctx.Err()
	case <-done:
	}
	local := p.pc.LocalDescription()
	if local == nil {
		return s, errors.New("missing local description")
	}
	return *local, nil
}
func (p *Peer) Offer(ctx context.Context) (webrtc.SessionDescription, error) {
	return p.description(ctx, true)
}
func (p *Peer) Answer(ctx context.Context, offer webrtc.SessionDescription, pin string) (webrtc.SessionDescription, error) {
	if offer.Type != webrtc.SDPTypeOffer {
		return webrtc.SessionDescription{}, errors.New("offer required")
	}
	if err := p.Remote(offer, pin); err != nil {
		return webrtc.SessionDescription{}, err
	}
	return p.description(ctx, false)
}

// Remote never disables Pion's DTLS certificate validation. It also binds the
// received SDP to the machine fingerprint authenticated by the control plane.
func (p *Peer) Remote(s webrtc.SessionDescription, pin string) error {
	if len(s.SDP) > 65536 || len(pin) != 95 {
		return errors.New("invalid pinned peer identity")
	}
	found := false
	for _, line := range strings.Split(s.SDP, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "a=fingerprint:") {
			parts := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "a=fingerprint:"))
			if len(parts) != 2 || parts[0] != "sha-256" || !strings.EqualFold(parts[1], pin) {
				return errors.New("peer certificate fingerprint mismatch")
			}
			found = true
		}
	}
	if !found {
		return errors.New("missing peer certificate fingerprint")
	}
	return p.pc.SetRemoteDescription(s)
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
	p.mu.RLock()
	dc := p.dc
	p.mu.RUnlock()
	if dc == nil || dc.ReadyState() != webrtc.DataChannelStateOpen {
		return ErrNotReady
	}
	if dc.BufferedAmount() > 256*1024 {
		return errors.New("private peer congested")
	}
	return dc.Send(b)
}
func (p *Peer) Close() error { return p.pc.Close() }
func (p *Peer) Path() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.path == "" || p.dc == nil || p.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return "", ErrNotReady
	}
	return p.path, nil
}
