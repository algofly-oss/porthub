package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algofly-oss/porthub/client/internal/policy"
)

// fakeControl mirrors the signaling rules of api/router/access/private.py:
// per-peer revisions, policy-neighbour peers only, lower-identity offers,
// signals bound to the target instance and dropped when the source restarts.
type fakeControl struct {
	mu      sync.Mutex
	tokens  map[string]string
	ips     map[string]string
	state   map[string]*fakePeer
	grants  []policy.Grant
	signals map[string]fakeSignal
	syncs   map[string]int
}
type fakePeer struct {
	fingerprint, instance string
	revision              uint64
	paths                 map[string]string
}
type fakeSignal struct {
	Signal
	sourceInstance, targetInstance string
}

func newFakeControl() *fakeControl {
	return &fakeControl{
		tokens:  map[string]string{"a": strings.Repeat("a", 32), "b": strings.Repeat("b", 32)},
		ips:     map[string]string{"a": "10.203.0.1", "b": "10.203.0.2"},
		state:   map[string]*fakePeer{},
		signals: map[string]fakeSignal{},
		syncs:   map[string]int{},
	}
}
func (f *fakeControl) setGrants(g []policy.Grant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants = g
}
func (f *fakeControl) path(id, remote string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p := f.state[id]; p != nil {
		return p.paths[remote]
	}
	return ""
}
func (f *fakeControl) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/api/access/private/sync" {
		http.NotFound(w, req)
		return
	}
	var in syncRequest
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens[in.PeerID] == "" || f.tokens[in.PeerID] != in.Token {
		http.Error(w, "revoked", 403)
		return
	}
	f.syncs[in.PeerID]++
	self := f.state[in.PeerID]
	if self == nil {
		self = &fakePeer{}
		f.state[in.PeerID] = self
	}
	self.fingerprint, self.instance, self.paths = in.Fingerprint, in.Instance, in.Paths
	self.revision++
	reachable := map[string]bool{in.PeerID: true}
	var grants []policy.Grant
	for _, g := range f.grants {
		if g.Source == in.PeerID || g.Destination == in.PeerID {
			grants = append(grants, g)
			reachable[g.Source], reachable[g.Destination] = true, true
		}
	}
	for _, s := range in.Signals {
		target := f.state[s.To]
		if !reachable[s.To] || target == nil || target.fingerprint == "" {
			continue
		}
		if (s.Description.Type.String() == "offer") != (in.PeerID < s.To) {
			http.Error(w, "direction", 400)
			return
		}
		id := in.PeerID + ":" + in.Instance + ":" + s.To + ":" + s.Session + ":" + s.Description.Type.String()
		if _, ok := f.signals[id]; !ok {
			s.ID, s.From = id, in.PeerID
			f.signals[id] = fakeSignal{s, in.Instance, target.instance}
		}
	}
	for _, id := range in.Acks {
		if s, ok := f.signals[id]; ok && s.To == in.PeerID {
			delete(f.signals, id)
		}
	}
	out := syncResponse{Signals: []Signal{}}
	for _, s := range f.signals {
		source := f.state[s.From]
		if s.To == in.PeerID && s.targetInstance == in.Instance && reachable[s.From] && source != nil && source.instance == s.sourceInstance {
			out.Signals = append(out.Signals, s.Signal)
		}
	}
	out.Snapshot = policy.Snapshot{Workspace: "workspace", Self: in.PeerID, Revision: self.revision, ExpiresAt: time.Now().Add(15 * time.Second), Grants: grants}
	for id := range reachable {
		p := policy.Peer{ID: id, IP: f.ips[id]}
		if s := f.state[id]; s != nil {
			p.Fingerprint, p.Instance = s.fingerprint, s.instance
		}
		out.Snapshot.Peers = append(out.Snapshot.Peers, p)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// memDevice stands in for the TUN: inject() is what local applications send,
// delivered is what arrives from the private network.
type memDevice struct {
	outbound  chan []byte
	delivered chan []byte
	closed    chan struct{}
	once      sync.Once
	mu        sync.Mutex
	routes    []netip.Addr
}

func newMemDevice() *memDevice {
	return &memDevice{outbound: make(chan []byte, 64), delivered: make(chan []byte, 64), closed: make(chan struct{})}
}
func (d *memDevice) Read(b []byte) (int, error) {
	select {
	case p := <-d.outbound:
		return copy(b, p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}
func (d *memDevice) Write(b []byte) (int, error) {
	select {
	case d.delivered <- append([]byte(nil), b...):
	default:
	}
	return len(b), nil
}
func (d *memDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}
func (d *memDevice) UpdateRoutes(r []netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routes = append([]netip.Addr(nil), r...)
	return nil
}
func (d *memDevice) inject(b []byte) { d.outbound <- b }

func tcp(src, dst string, sport, dport uint16, flags byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 40)
	b[8] = 64
	b[9] = 6
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	b[32], b[33] = 0x50, flags
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:12], ^uint16(sum))
	return b
}

const (
	syn    = 0x02
	synAck = 0x12
	ack    = 0x10
)

type node struct {
	runtime *Runtime
	dev     *memDevice
	done    chan error
	cancel  context.CancelFunc
}

func start(t *testing.T, server, id string, control *fakeControl) *node {
	t.Helper()
	r, err := New(Config{Server: server, PeerID: id, Token: control.tokens[id], Workspace: "workspace", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	dev := newMemDevice()
	r.loopback = true
	r.open = func(name string, self netip.Addr, routes []netip.Addr) (Device, error) {
		if !strings.HasPrefix(name, "ph") || self.String() != control.ips[id] {
			return nil, errors.New("unexpected interface")
		}
		return dev, dev.UpdateRoutes(routes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &node{runtime: r, dev: dev, done: make(chan error, 1), cancel: cancel}
	go func() { n.done <- r.Run(ctx) }()
	return n
}
func (n *node) stop(t *testing.T) error {
	t.Helper()
	n.cancel()
	select {
	case err := <-n.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("runtime did not stop")
		return nil
	}
}
func eventually(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// expect waits for a matching packet; any other delivered packet is a failure.
func expect(t *testing.T, d *memDevice, want []byte) {
	t.Helper()
	select {
	case got := <-d.delivered:
		if string(got) != string(want) {
			t.Fatalf("unexpected packet delivered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("permitted packet was not delivered")
	}
}
func expectNothing(t *testing.T, d *memDevice) {
	t.Helper()
	select {
	case <-d.delivered:
		t.Fatal("denied packet was delivered")
	case <-time.After(700 * time.Millisecond):
	}
}

func TestRuntimeEndToEndPolicyAndReconnect(t *testing.T) {
	control := newFakeControl()
	control.setGrants([]policy.Grant{{Source: "a", Destination: "b", Protocol: "tcp", Ports: []policy.PortRange{{Start: 80, End: 80}}}})
	server := httptest.NewServer(control)
	defer server.Close()
	a, b := start(t, server.URL, "a", control), start(t, server.URL, "b", control)
	defer a.stop(t)
	connected := func() bool { return control.path("a", "b") == "direct" && control.path("b", "a") == "direct" }
	began := time.Now()
	eventually(t, 30*time.Second, "direct connection", connected)
	t.Logf("initial connection after %v", time.Since(began).Round(time.Millisecond))

	// Permitted one-way flow, including the reply direction.
	open := tcp("10.203.0.1", "10.203.0.2", 40000, 80, syn)
	a.dev.inject(open)
	expect(t, b.dev, open)
	reply := tcp("10.203.0.2", "10.203.0.1", 80, 40000, synAck)
	b.dev.inject(reply)
	expect(t, a.dev, reply)
	a.dev.inject(tcp("10.203.0.1", "10.203.0.2", 40000, 80, ack))
	<-b.dev.delivered

	// Other ports and the reverse direction stay denied by default.
	a.dev.inject(tcp("10.203.0.1", "10.203.0.2", 40001, 81, syn))
	expectNothing(t, b.dev)
	b.dev.inject(tcp("10.203.0.2", "10.203.0.1", 40002, 80, syn))
	expectNothing(t, a.dev)

	// Removing the grant stops the established flow at the next lease.
	control.setGrants(nil)
	eventually(t, 5*time.Second, "policy removal", func() bool {
		control.mu.Lock()
		before := control.syncs["b"]
		control.mu.Unlock()
		time.Sleep(1100 * time.Millisecond)
		control.mu.Lock()
		defer control.mu.Unlock()
		return control.syncs["b"] > before
	})
	b.dev.inject(tcp("10.203.0.2", "10.203.0.1", 80, 40000, ack))
	expectNothing(t, a.dev)

	// A restarted peer (new certificate and instance) reconnects by itself.
	control.setGrants([]policy.Grant{{Source: "a", Destination: "b", Protocol: "tcp", Ports: []policy.PortRange{{Start: 80, End: 80}}}})
	if err := b.stop(t); err != nil {
		t.Fatal(err)
	}
	b = start(t, server.URL, "b", control)
	defer b.stop(t)
	began = time.Now()
	eventually(t, 30*time.Second, "reconnection", func() bool {
		control.mu.Lock()
		restarted := control.state["b"].instance == b.runtime.instance
		control.mu.Unlock()
		return restarted && connected()
	})
	t.Logf("reconnection after restart %v", time.Since(began).Round(time.Millisecond))
	again := tcp("10.203.0.1", "10.203.0.2", 40003, 80, syn)
	a.dev.inject(again)
	expect(t, b.dev, again)
}

func TestRuntimeExitsAndRevokesWhenCredentialRejected(t *testing.T) {
	control := newFakeControl()
	server := httptest.NewServer(control)
	defer server.Close()
	a := start(t, server.URL, "a", control)
	eventually(t, 5*time.Second, "first sync", func() bool {
		control.mu.Lock()
		defer control.mu.Unlock()
		return control.syncs["a"] > 0
	})
	control.mu.Lock()
	control.tokens["a"] = strings.Repeat("x", 32)
	control.mu.Unlock()
	select {
	case err := <-a.done:
		var rejected Rejected
		if !errors.As(err, &rejected) || rejected.Code != 403 {
			t.Fatalf("expected 403 exit, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked runtime kept running")
	}
	select {
	case <-a.dev.closed:
	default:
		t.Fatal("private interface left open after revocation")
	}
}

func TestQueueRejectsSignalsForReplacedSessions(t *testing.T) {
	r := &Runtime{peers: map[string]*peerSession{}, wake: make(chan struct{}, 1)}
	old, current := &peerSession{session: "old-session-0000"}, &peerSession{session: "new-session-0000"}
	r.peers["b"] = current
	r.queue("b", old, Signal{To: "b", Session: "old-session-0000"})
	r.queue("b", current, Signal{To: "b", Session: "old-session-0000"})
	if len(r.pending) != 0 {
		t.Fatal("stale negotiation queued")
	}
	r.queue("b", current, Signal{To: "b", Session: "new-session-0000"})
	if len(r.pending) != 1 {
		t.Fatal("current negotiation not queued")
	}
	// Sent entries are removed by identity even if the queue changed meanwhile.
	sent := map[uint64]bool{r.pending[0].seq: true}
	r.dropPendingLocked("b")
	r.seq++
	r.pending = append(r.pending, queuedSignal{r.seq, Signal{To: "d"}})
	if got := removeSent(r.pending, sent); len(got) != 1 || got[0].signal.To != "d" {
		t.Fatal("unsent signal lost")
	}
}
