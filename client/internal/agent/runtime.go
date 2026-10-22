package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/algofly-oss/porthub/client/internal/device"
	"github.com/algofly-oss/porthub/client/internal/mesh"
	"github.com/algofly-oss/porthub/client/internal/names"
	"github.com/algofly-oss/porthub/client/internal/policy"
	"github.com/algofly-oss/porthub/client/internal/relay"
	"github.com/pion/webrtc/v4"
)

// Device is the private packet interface. Production uses an owned Linux TUN;
// tests substitute an in-memory device so the runtime runs without root.
type Device interface {
	io.ReadWriteCloser
	UpdateRoutes([]netip.Addr) error
}

// A negotiation that has not opened its data channel within this window is
// restarted (gathering may take up to gatherTimeout on each side).
const negotiationTimeout = 40 * time.Second

// gatherTimeout bounds candidate gathering (STUN and relay allocation)
// before an offer or answer is sent.
const gatherTimeout = 20 * time.Second

// peerSession fields other than info and peer are guarded by Runtime.mu.
type peerSession struct {
	info    policy.Peer
	peer    *mesh.Peer
	session string
	started time.Time
}
type queuedSignal struct {
	seq    uint64
	signal Signal
}
type Runtime struct {
	config                Config
	control               *Control
	engine                *policy.Engine
	cert                  *webrtc.Certificate
	fingerprint, instance string
	open                  func(name string, self netip.Addr, routes []netip.Addr) (Device, error)
	loopback              bool
	meshOptions           []mesh.Option // tests only
	mu                    sync.Mutex
	tun                   Device
	selfIP                netip.Addr
	peers                 map[string]*peerSession
	byIP                  map[netip.Addr]string
	pending               []queuedSignal
	seq                   uint64
	acks                  []string
	seen                  map[string]time.Time
	err                   chan error
	wake                  chan struct{}
	names                 *names.Server
	ifindex               int
	domain                string
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func openTUN(name string, self netip.Addr, routes []netip.Addr) (Device, error) {
	return device.Open(name, self, routes)
}
func New(c Config) (*Runtime, error) {
	control, err := NewControl(c)
	if err != nil {
		return nil, err
	}
	cert, err := mesh.Certificate()
	if err != nil {
		return nil, err
	}
	fingerprint, err := mesh.Fingerprint(cert)
	if err != nil {
		return nil, err
	}
	instance, err := randomID()
	if err != nil {
		return nil, err
	}
	return &Runtime{config: c, control: control, cert: cert, fingerprint: fingerprint, instance: instance, open: openTUN, engine: policy.New(), peers: make(map[string]*peerSession), byIP: make(map[netip.Addr]string), seen: make(map[string]time.Time), err: make(chan error, 1), wake: make(chan struct{}, 1)}, nil
}
func (r *Runtime) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer r.close()
	defer cancel() // runs first: the reader sees cancellation, not an error
	if r.config.AllowInsecureHTTP {
		log.Print("WARNING: test profile uses unencrypted HTTP control; never use this profile on an untrusted network")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastError time.Time
	for {
		if err := r.step(ctx); err != nil {
			var rejected Rejected
			if errors.As(err, &rejected) && (rejected.Code == 403 || rejected.Code == 410) {
				r.engine.Revoke()
				return err
			}
			if time.Since(lastError) > 10*time.Second {
				log.Printf("private sync unavailable; policy lease will fail closed: %v", err)
				lastError = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-r.err:
			return err
		case <-ticker.C:
		case <-r.wake:
			// Deliver negotiation immediately instead of waiting for the tick.
		}
	}
}

// step performs one sync. Only the signals and acknowledgements actually sent
// are removed afterwards, so entries dropped or added meanwhile are unaffected.
func (r *Runtime) step(ctx context.Context) error {
	r.mu.Lock()
	n, a := min(16, len(r.pending)), min(128, len(r.acks))
	request := syncRequest{Fingerprint: r.fingerprint, Instance: r.instance, Signals: make([]Signal, 0, n), Acks: append([]string{}, r.acks[:a]...), Paths: make(map[string]string)}
	sent := make(map[uint64]bool, n)
	for _, q := range r.pending[:n] {
		request.Signals = append(request.Signals, q.signal)
		sent[q.seq] = true
	}
	for id, p := range r.peers {
		path, err := p.peer.Path()
		if err != nil {
			path = "connecting"
		}
		request.Paths[id] = path
	}
	r.mu.Unlock()
	response, err := r.control.sync(ctx, request)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.pending = removeSent(r.pending, sent)
	acked := make(map[string]bool, a)
	for _, id := range request.Acks {
		acked[id] = true
	}
	acks := r.acks[:0]
	for _, id := range r.acks {
		if !acked[id] {
			acks = append(acks, id)
		}
	}
	r.acks = acks
	r.mu.Unlock()
	if err = r.configure(ctx, response); err != nil {
		r.engine.Revoke()
		select {
		case r.err <- err:
		default:
		}
		return err
	}
	return nil
}
func removeSent(pending []queuedSignal, sent map[uint64]bool) []queuedSignal {
	kept := pending[:0]
	for _, q := range pending {
		if !sent[q.seq] {
			kept = append(kept, q)
		}
	}
	return kept
}

// dropPendingLocked discards unsent negotiation for a peer whose session was
// replaced; a stale offer delivered later would reset the new session.
func (r *Runtime) dropPendingLocked(id string) {
	kept := r.pending[:0]
	for _, q := range r.pending {
		if q.signal.To != id {
			kept = append(kept, q)
		}
	}
	r.pending = kept
}
func (r *Runtime) configure(ctx context.Context, response syncResponse) error {
	s := response.Snapshot
	if err := r.engine.Apply(s); err != nil {
		return err
	}
	var self netip.Addr
	var routes []netip.Addr
	wanted := make(map[string]policy.Peer)
	for _, peer := range s.Peers {
		ip := netip.MustParseAddr(peer.IP)
		if peer.ID == s.Self {
			self = ip
		} else {
			routes = append(routes, ip)
			wanted[peer.ID] = peer
		}
	}
	r.mu.Lock()
	tun, oldIP := r.tun, r.selfIP
	r.mu.Unlock()
	if tun == nil {
		hash := sha256.Sum256([]byte(s.Workspace))
		name := "ph" + hex.EncodeToString(hash[:4])
		var err error
		tun, err = r.open(name, self, routes)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.tun = tun
		r.selfIP = self
		r.mu.Unlock()
		log.Printf("private interface %s ready at %s; no default route or public mappings changed", name, self)
		go r.readPackets(ctx, tun)
		r.startNames(tun, self, s)
	} else {
		if self != oldIP {
			return errors.New("private address changed; restart the private client to reconfigure safely")
		}
		if err := tun.UpdateRoutes(routes); err != nil {
			return err
		}
	}
	r.updateNames(s)
	var closePeers []*mesh.Peer
	r.mu.Lock()
	r.byIP = make(map[netip.Addr]string)
	for id, info := range wanted {
		r.byIP[netip.MustParseAddr(info.IP)] = id
	}
	for id, current := range r.peers {
		info, ok := wanted[id]
		if !ok || info.Fingerprint != current.info.Fingerprint || info.Instance != current.info.Instance || current.peer.Failed() || (!current.peer.Ready() && time.Since(current.started) > negotiationTimeout) {
			delete(r.peers, id)
			r.dropPendingLocked(id)
			closePeers = append(closePeers, current.peer)
		}
	}
	for id, at := range r.seen {
		if time.Since(at) > time.Minute {
			delete(r.seen, id)
		}
	}
	r.mu.Unlock()
	for _, p := range closePeers {
		_ = p.Close()
	}
	for id, info := range wanted {
		if info.Fingerprint == "" || info.Instance == "" {
			continue
		}
		r.mu.Lock()
		exists := r.peers[id] != nil
		r.mu.Unlock()
		if exists {
			continue
		}
		current, err := r.newPeer(info, response.ICEServers)
		if err != nil {
			return err
		}
		// The lower identity offers. Its session is fixed before the peer is
		// published, so an answer can never be compared with a half-set value.
		if s.Self < id {
			if current.session, err = randomID(); err != nil {
				_ = current.peer.Close()
				return err
			}
		}
		r.mu.Lock()
		r.peers[id] = current
		r.mu.Unlock()
		if current.session != "" {
			go r.makeOffer(ctx, id, current, current.session)
		}
	}
	for _, signal := range response.Signals {
		if err := r.handleSignal(ctx, s.Self, signal, response.ICEServers); err != nil {
			return err
		}
	}
	return nil
}
func (r *Runtime) handleSignal(ctx context.Context, self string, signal Signal, servers []webrtc.ICEServer) error {
	r.mu.Lock()
	_, seen := r.seen[signal.ID]
	current := r.peers[signal.From]
	r.acks = append(r.acks, signal.ID)
	if !seen {
		r.seen[signal.ID] = time.Now()
	}
	var session string
	if current != nil {
		session = current.session
	}
	r.mu.Unlock()
	if seen || current == nil {
		return nil
	}
	switch {
	case signal.Description.Type == webrtc.SDPTypeAnswer && self < signal.From:
		if signal.Session != session {
			return nil
		}
		if err := current.peer.Remote(signal.Description, current.info.Fingerprint); err != nil {
			log.Printf("private answer rejected: %v", err)
		}
	case signal.Description.Type == webrtc.SDPTypeOffer && self > signal.From:
		if session != "" {
			// The offerer restarted its side; answer on a fresh connection.
			replacement, err := r.newPeer(current.info, servers)
			if err != nil {
				return err
			}
			r.mu.Lock()
			if r.peers[signal.From] != current {
				r.mu.Unlock()
				_ = replacement.peer.Close()
				return nil
			}
			r.peers[signal.From] = replacement
			r.dropPendingLocked(signal.From)
			r.mu.Unlock()
			_ = current.peer.Close()
			current = replacement
		}
		r.mu.Lock()
		if r.peers[signal.From] != current {
			r.mu.Unlock()
			return nil
		}
		current.session = signal.Session
		// The negotiation timeout runs from the offer, not from when the
		// answering side first learned about its peer.
		current.started = time.Now()
		r.mu.Unlock()
		go r.makeAnswer(ctx, signal.From, current, signal.Session, signal.Description)
	}
	return nil
}

// relayOptions routes TURN-over-TCP through the gateway's WebSocket relay on
// the same address the agent syncs with (no extra port; CDN friendly).
func (r *Runtime) relayOptions(servers []webrtc.ICEServer) []mesh.Option {
	for _, server := range servers {
		for _, u := range server.URLs {
			if strings.HasPrefix(u, "turn:") {
				if endpoint, err := relay.URLFor(r.config.Server); err == nil {
					return append(r.meshOptions, mesh.WithRelay(relay.Dialer{URL: endpoint}))
				}
			}
		}
	}
	return r.meshOptions
}

func (r *Runtime) newPeer(info policy.Peer, servers []webrtc.ICEServer) (*peerSession, error) {
	p, err := mesh.New(r.cert, servers, r.loopback, func(packet []byte) {
		if !r.engine.Check(packet, info.ID, true) {
			return
		}
		r.mu.Lock()
		tun := r.tun
		r.mu.Unlock()
		if tun != nil {
			_, _ = tun.Write(packet)
		}
	}, r.relayOptions(servers)...)
	if err != nil {
		return nil, err
	}
	return &peerSession{info: info, peer: p, started: time.Now()}, nil
}
func (r *Runtime) makeOffer(ctx context.Context, id string, current *peerSession, session string) {
	ctx, cancel := context.WithTimeout(ctx, gatherTimeout)
	defer cancel()
	description, err := current.peer.Offer(ctx)
	if err != nil {
		log.Printf("private offer to %s not sent: %v", id, err)
		return
	}
	r.queue(id, current, Signal{To: id, Session: session, Description: description})
}
func (r *Runtime) makeAnswer(ctx context.Context, id string, current *peerSession, session string, offer webrtc.SessionDescription) {
	ctx, cancel := context.WithTimeout(ctx, gatherTimeout)
	defer cancel()
	description, err := current.peer.Answer(ctx, offer, current.info.Fingerprint)
	if err != nil {
		log.Printf("private offer rejected: %v", err)
		return
	}
	r.queue(id, current, Signal{To: id, Session: session, Description: description})
}

// queue accepts a signal only while its session is still the current one.
func (r *Runtime) queue(id string, current *peerSession, message Signal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers[id] == current && current.session == message.Session && len(r.pending) < 1024 {
		r.seq++
		r.pending = append(r.pending, queuedSignal{r.seq, message})
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}
func (r *Runtime) readPackets(ctx context.Context, tun Device) {
	buffer := make([]byte, 65536)
	for {
		n, err := tun.Read(buffer)
		if err != nil {
			if ctx.Err() == nil {
				select {
				case r.err <- fmt.Errorf("read private interface: %w", err):
				default:
				}
			}
			return
		}
		if n > mesh.MaxPacket {
			continue
		}
		b := buffer[:n]
		packet, err := policy.Parse(b)
		if err != nil {
			continue
		}
		r.mu.Lock()
		id := r.byIP[packet.Destination]
		current := r.peers[id]
		r.mu.Unlock()
		// Pion copies the payload before Send returns, so the buffer is reusable.
		if current != nil && r.engine.Check(b, id, false) {
			_ = current.peer.Send(b)
		}
	}
}

// suffix is the private DNS domain: everything after the first label of the
// controller-assigned hostname of this machine.
func suffix(s policy.Snapshot) string {
	for _, p := range s.Peers {
		if p.ID == s.Self {
			if _, rest, ok := strings.Cut(p.Hostname, "."); ok {
				return rest
			}
		}
	}
	return ""
}

// startNames serves private peer names on the interface address and routes
// only the private suffix there. Failure leaves IP access fully working.
func (r *Runtime) startNames(tun Device, self netip.Addr, s policy.Snapshot) {
	link, ok := tun.(interface{ Index() int })
	domain := suffix(s)
	if !ok || domain == "" {
		return
	}
	server, err := names.Listen(netip.AddrPortFrom(self, 53))
	if err != nil {
		log.Printf("private names unavailable (use addresses): %v", err)
		return
	}
	if err = names.RegisterLink(link.Index(), self, domain); err != nil {
		log.Printf("private names unavailable; systemd-resolved did not accept the link (use addresses): %v", err)
		server.Close()
		return
	}
	r.mu.Lock()
	r.names, r.ifindex, r.domain = server, link.Index(), domain
	r.mu.Unlock()
	log.Printf("private names *.%s resolved on %s; other DNS unchanged", domain, self)
}
func (r *Runtime) updateNames(s policy.Snapshot) {
	r.mu.Lock()
	server, ifindex, previous := r.names, r.ifindex, r.domain
	r.mu.Unlock()
	if server == nil {
		return
	}
	// The workspace may rename its suffix; re-route the new one only.
	if domain := suffix(s); domain != "" && domain != previous {
		if err := names.RegisterLink(ifindex, r.selfIP, domain); err != nil {
			log.Printf("private names: could not switch to *.%s: %v", domain, err)
		} else {
			r.mu.Lock()
			r.domain = domain
			r.mu.Unlock()
			log.Printf("private names now *.%s", domain)
		}
	}
	records := make(map[string]netip.Addr)
	for _, p := range s.Peers {
		ip := netip.MustParseAddr(p.IP)
		if p.Hostname != "" {
			records[p.Hostname] = ip
		}
		for _, alias := range p.Aliases {
			records[alias] = ip
		}
	}
	server.Update(suffix(s), records)
}

func (r *Runtime) close() {
	r.engine.Revoke()
	r.mu.Lock()
	server, ifindex := r.names, r.ifindex
	r.names = nil
	r.mu.Unlock()
	if server != nil {
		names.Unregister(ifindex)
		server.Close()
	}
	r.mu.Lock()
	tun := r.tun
	peers := r.peers
	r.peers = make(map[string]*peerSession)
	r.tun = nil
	r.mu.Unlock()
	if tun != nil {
		_ = tun.Close()
	}
	for _, p := range peers {
		_ = p.peer.Close()
	}
}
