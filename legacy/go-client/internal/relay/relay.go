// Package relay carries private-network traffic through the PortHub gateway
// when no direct path works. It is a standard TURN server (pion/turn) whose
// client connections arrive as WebSockets on the PortHub web address, so the
// relay needs no extra port and can ride a CDN (e.g. Cloudflare) that reaches
// home networks far faster than a direct cloud-to-home TCP flow.
//
// Peer traffic stays end-to-end encrypted by DTLS; the relay only forwards
// packets between allocations on its own loopback and refuses any other
// destination.
package relay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/turn/v5"
)

const Realm = "porthub"

// Path is where the gateway serves the relay WebSocket.
const Path = "/api/access/private/relay"

// tcpConn reports TCP addresses, which pion's TURN-over-TCP code requires.
type tcpConn struct {
	net.Conn
	local, remote *net.TCPAddr
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.local }
func (c *tcpConn) RemoteAddr() net.Addr { return c.remote }

// tcpAddr parses a literal IP:port and never resolves names, so a request's
// Host header cannot trigger DNS lookups.
func tcpAddr(s string) *net.TCPAddr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}

// listener turns accepted WebSockets into connections for the TURN server.
type listener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *listener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

type Server struct {
	turn     *turn.Server
	listener *listener
	sem      chan struct{}
	secret   string
	noise    []byte
}

// loopbackOnly lets allocations reach only other allocations of this relay.
func loopbackOnly(_ net.Addr, peer net.IP) bool { return peer.IsLoopback() }

// NewServer starts a TURN server authenticating time-limited credentials
// signed with secret (TURN REST: username "expiry:peer", HMAC-SHA1 password).
func NewServer(secret string, maxConnections int) (*Server, error) {
	if len(secret) < 32 {
		return nil, errors.New("relay secret must be at least 32 characters")
	}
	l := &listener{conns: make(chan net.Conn), closed: make(chan struct{})}
	t, err := turn.NewServer(turn.ServerConfig{
		Realm:       Realm,
		AuthHandler: turn.LongTermTURNRESTAuthHandler(secret, nil),
		ListenerConfigs: []turn.ListenerConfig{{
			Listener:              l,
			RelayAddressGenerator: newMemoryNet(),
			PermissionHandler:     loopbackOnly,
		}},
	})
	if err != nil {
		return nil, err
	}
	noise := make([]byte, 1<<20)
	_, _ = rand.Read(noise) // incompressible, so a CDN cannot shortcut the test
	return &Server{turn: t, listener: l, sem: make(chan struct{}, maxConnections), secret: secret, noise: noise}, nil
}

func (s *Server) Close() error {
	s.listener.Close()
	return s.turn.Close()
}

// Handler routes the relay WebSocket and the route speed test.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(Path, s)
	mux.Handle(SpeedPath, s)
	return mux
}

// SpeedPath measures a route to the relay: GET downloads, POST uploads.
const SpeedPath = Path + "/speedtest"

const maxSpeedBytes = 32 << 20

// ServeHTTP serves the relay WebSocket, and the route speed test for holders
// of a valid relay credential.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == SpeedPath {
		s.speedTest(w, r)
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		http.Error(w, "relay busy", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-s.sem }()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go keepalive(ctx, ws)
	conn := &tcpConn{Conn: websocket.NetConn(ctx, ws, websocket.MessageBinary), local: tcpAddr(r.Host), remote: tcpAddr(r.RemoteAddr)}
	done := make(chan struct{})
	tracked := &closeNotify{Conn: conn, done: done}
	select {
	case s.listener.conns <- tracked:
	case <-s.listener.closed:
		conn.Close()
		return
	}
	<-done
}

// speedTest lets an agent compare routes (CDN vs direct) to this relay. It
// requires the same short-lived credential as the relay so it cannot be used
// as an open bandwidth sink.
func (s *Server) speedTest(w http.ResponseWriter, r *http.Request) {
	user, credential := r.Header.Get("X-Relay-User"), r.Header.Get("X-Relay-Credential")
	if !ValidCredential(s.secret, user, credential) {
		http.Error(w, "relay credential required", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		n = min(max(n, 0), maxSpeedBytes)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		for n > 0 {
			chunk := s.noise[:min(n, len(s.noise))]
			if _, err := w.Write(chunk); err != nil {
				return
			}
			n -= len(chunk)
		}
	case http.MethodPost:
		read, _ := io.Copy(io.Discard, io.LimitReader(r.Body, maxSpeedBytes))
		fmt.Fprint(w, read)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ValidCredential checks a TURN REST credential ("expiry:user", base64
// HMAC-SHA1 of it with the shared secret) and its expiry.
func ValidCredential(secret, user, credential string) bool {
	expiry, _, ok := strings.Cut(user, ":")
	t, err := strconv.ParseInt(expiry, 10, 64)
	if !ok || err != nil || t < time.Now().Unix() {
		return false
	}
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(user))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(credential))
}

// closeNotify lets ServeHTTP return once the TURN server closes the stream.
type closeNotify struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// Read also ends the handler when the WebSocket stops delivering data: the
// TURN server finishes its read loop then but does not always Close.
func (c *closeNotify) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.once.Do(func() { close(c.done) })
	}
	return n, err
}
func (c *closeNotify) LocalAddr() net.Addr  { return c.Conn.LocalAddr() }
func (c *closeNotify) RemoteAddr() net.Addr { return c.Conn.RemoteAddr() }

// keepalive pings so proxies (Cloudflare closes idle WebSockets after 100s)
// keep the relay open between bursts.
func keepalive(ctx context.Context, ws *websocket.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = ws.Ping(pctx)
			cancel()
		}
	}
}

// Dialer opens relay connections over WebSocket. pion ICE calls Dial for
// "turn:...?transport=tcp" servers; the TURN URL host is not used.
type Dialer struct {
	URL string // ws:// or wss:// relay endpoint
}

// URLFor derives the relay endpoint from the PortHub control server URL.
func URLFor(server string) (string, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", errors.New("unsupported server scheme")
	}
	u.Path += Path
	return u.String(), nil
}

func (d Dialer) Dial(_, _ string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, response, err := websocket.Dial(ctx, d.URL, nil)
	if err != nil {
		if response != nil {
			log.Printf("relay unavailable: HTTP %d", response.StatusCode)
		}
		return nil, err
	}
	ws.SetReadLimit(1 << 20)
	streamCtx, stop := context.WithCancel(context.Background())
	go keepalive(streamCtx, ws)
	conn := websocket.NetConn(streamCtx, ws, websocket.MessageBinary)
	return &tcpConn{Conn: &stopOnClose{Conn: conn, stop: stop}, local: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, remote: &net.TCPAddr{IP: net.IPv4zero}}, nil
}

type stopOnClose struct {
	net.Conn
	stop context.CancelFunc
}

func (c *stopOnClose) Close() error {
	c.stop()
	return c.Conn.Close()
}
