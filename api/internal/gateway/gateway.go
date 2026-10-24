// Package gateway implements PortHub's TCP forwarding gateway in the API.
// The authentication/control protocol interoperates with Rathole v0.5.0
// (Apache-2.0); see its src/protocol.rs and src/server.rs. API WebSockets use
// PortHub's framed stream to retain TCP half-close across HTTPS proxies.
package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/algofly-oss/porthub/client/transport"
	"github.com/coder/websocket"
)

type Service struct {
	Token string `toml:"token"`
	Bind  string `toml:"bind_addr"`
	Type  string `toml:"type"`
}
type Config struct{ Services map[string]Service }

func Parse(data []byte) (Config, error) {
	var raw struct {
		Server struct{ Services map[string]Service }
	}
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return Config{}, err
	}
	if raw.Server.Services == nil {
		return Config{}, errors.New("gateway services missing")
	}
	seen := map[string]bool{}
	for name, s := range raw.Server.Services {
		if name == "dummy" {
			delete(raw.Server.Services, name)
			continue
		}
		if s.Token == "" {
			return Config{}, fmt.Errorf("service %s: missing credential", name)
		}
		if s.Type != "" && s.Type != "tcp" {
			return Config{}, fmt.Errorf("service %s: unsupported type", name)
		}
		if _, _, err := net.SplitHostPort(s.Bind); err != nil {
			return Config{}, fmt.Errorf("service %s: invalid bind address", name)
		}
		if seen[s.Bind] {
			return Config{}, errors.New("duplicate gateway bind address")
		}
		seen[s.Bind] = true
	}
	return Config{raw.Server.Services}, nil
}

type Gateway struct {
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	services   map[[32]byte]*service
	sessions   map[[32]byte]*session
	handshakes chan struct{}
}
type service struct {
	config   Service
	listener net.Listener
	session  *session
	slots    chan struct{}
}
type session struct {
	ctx      context.Context
	cancel   context.CancelFunc
	key      [32]byte
	conn     net.Conn
	data     chan *dataConn
	requests chan struct{}
}
type dataConn struct {
	net.Conn
	done chan struct{}
}

func New(ctx context.Context) *Gateway {
	ctx, cancel := context.WithCancel(ctx)
	return &Gateway{ctx: ctx, cancel: cancel, services: map[[32]byte]*service{}, sessions: map[[32]byte]*session{}, handshakes: make(chan struct{}, 1024)}
}

// Apply keeps unchanged listeners and sessions alive; removals and token changes
// revoke both queued channels and active streams immediately.
func (g *Gateway) Apply(config Config) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return net.ErrClosed
	}
	wanted := map[[32]byte]Service{}
	for name, c := range config.Services {
		wanted[sha256.Sum256([]byte(name))] = c
	}
	for key, s := range g.services {
		c, ok := wanted[key]
		if !ok || c != s.config {
			if s.session != nil {
				s.session.cancel()
				delete(g.sessions, s.session.key)
			}
			_ = s.listener.Close()
			delete(g.services, key)
		}
	}
	var failures []error
	for key, c := range wanted {
		if g.services[key] != nil {
			continue
		}
		l, err := net.Listen("tcp", c.Bind)
		if err != nil {
			failures = append(failures, fmt.Errorf("gateway bind %s: %w", c.Bind, err))
			continue
		}
		s := &service{config: c, listener: l, slots: make(chan struct{}, 512)}
		g.services[key] = s
		go g.acceptVisitors(s)
	}
	return errors.Join(failures...)
}

func (g *Gateway) Close() {
	g.cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.services {
		_ = s.listener.Close()
		if s.session != nil {
			s.session.cancel()
		}
	}
}

// ServeLegacy is migration-only. New agents use Handler on the API listener.
func (g *Gateway) ServeLegacy(l net.Listener) error {
	stop := context.AfterFunc(g.ctx, func() { _ = l.Close() })
	defer stop()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go g.Handle(c)
	}
}

func (g *Gateway) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), transport.Subprotocol) {
		g.upgrade(w, r)
		return
	}
	if !contains(strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ","), transport.Subprotocol) {
		http.Error(w, "PortHub tunnel subprotocol required", 400)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{transport.Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	c := transport.New(ws)
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	go c.KeepAlive(ctx)
	g.Handle(c)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (g *Gateway) upgrade(w http.ResponseWriter, r *http.Request) {
	if !contains(strings.Split(r.Header.Get("Connection"), ","), "Upgrade") && !contains(strings.Split(r.Header.Get("Connection"), ","), "upgrade") {
		http.Error(w, "Upgrade connection required", 400)
		return
	}
	conn, buffer, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "HTTP Upgrade unavailable", 400)
		return
	}
	if _, err = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", transport.Subprotocol); err == nil {
		err = buffer.Flush()
	}
	if err != nil {
		conn.Close()
		return
	}
	var raw net.Conn = conn
	if buffer.Reader.Buffered() > 0 {
		raw = &bufferedConn{Conn: conn, reader: buffer.Reader}
	}
	stream := transport.Wrap(raw)
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	go stream.KeepAlive(ctx)
	g.Handle(stream)
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}

func (g *Gateway) Handle(c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(g.ctx, func() { _ = c.Close() })
	defer stop()
	select {
	case g.handshakes <- struct{}{}:
	default:
		return
	}
	held := true
	release := func() {
		if held {
			<-g.handshakes
			held = false
		}
	}
	defer release()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var hello [37]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil || hello[4] != 1 {
		return
	}
	kind := binary.LittleEndian.Uint32(hello[:4])
	var key [32]byte
	copy(key[:], hello[5:])
	if kind == 1 {
		g.mu.Lock()
		s := g.sessions[key]
		g.mu.Unlock()
		if s == nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		release()
		d := &dataConn{c, make(chan struct{})}
		select {
		case s.data <- d:
		case <-s.ctx.Done():
			return
		default:
			return
		}
		select {
		case <-d.done:
		case <-s.ctx.Done():
		}
		return
	}
	if kind != 0 {
		return
	}
	// Rathole sends the nonce before looking up the service.
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	reply := make([]byte, 37)
	reply[4] = 1
	copy(reply[5:], nonce[:])
	if _, err := c.Write(reply); err != nil {
		return
	}
	g.mu.Lock()
	svc := g.services[key]
	g.mu.Unlock()
	if svc == nil {
		_ = writeCommand(c, 1)
		return
	}
	auth := sha256.Sum256(append([]byte(svc.config.Token), nonce[:]...))
	var received [32]byte
	if _, err := io.ReadFull(c, received[:]); err != nil {
		return
	}
	if subtle.ConstantTimeCompare(auth[:], received[:]) != 1 {
		_ = writeCommand(c, 2)
		return
	}
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	s := &session{ctx: ctx, cancel: cancel, key: auth, conn: c, data: make(chan *dataConn, 16), requests: make(chan struct{}, 512)}
	g.mu.Lock()
	if g.services[key] != svc {
		g.mu.Unlock()
		return
	}
	if svc.session != nil {
		svc.session.cancel()
		delete(g.sessions, svc.session.key)
	}
	svc.session = s
	g.sessions[auth] = s
	g.mu.Unlock()
	protocol := "tcp"
	if stream, ok := c.(interface{ Protocol() string }); ok {
		protocol = stream.Protocol()
	}
	log.Printf("PortHub gateway: authenticated %s forwarding session on %s", protocol, svc.config.Bind)
	defer func() {
		g.mu.Lock()
		if svc.session == s {
			svc.session = nil
		}
		delete(g.sessions, auth)
		g.mu.Unlock()
	}()
	stopSession := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stopSession()
	if err := writeCommand(c, 0); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	release()
	// A control channel has no client-to-server messages after authentication.
	go func() { var b [1]byte; _, _ = c.Read(b[:]); cancel() }()
	for i := 0; i < 8; i++ {
		s.requests <- struct{}{}
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		command := uint32(0)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			command = 1
		case <-s.requests:
		}
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := writeCommand(c, command); err != nil {
			return
		}
	}
}

func writeCommand(c net.Conn, command uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], command)
	_, err := c.Write(b[:])
	return err
}

func (g *Gateway) acceptVisitors(s *service) {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case s.slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() { defer func() { <-s.slots }(); defer c.Close(); g.forward(s, c) }()
	}
}

func (g *Gateway) forward(svc *service, visitor net.Conn) {
	g.mu.Lock()
	s := svc.session
	g.mu.Unlock()
	if s == nil {
		return
	}
	stop := context.AfterFunc(s.ctx, func() { _ = visitor.Close() })
	defer stop()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	// Request before waiting: bursts can establish channels concurrently,
	// and a failed prewarm cannot leave an otherwise healthy session stalled.
	select {
	case s.requests <- struct{}{}:
	case <-s.ctx.Done():
		return
	}
	var data *dataConn
	select {
	case data = <-s.data:
	case <-s.ctx.Done():
		return
	case <-timer.C:
		return
	}
	defer close(data.done)
	defer data.Close()
	if err := writeCommand(data.Conn, 0); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		var err error
		if stream, ok := dst.(*transport.Stream); ok {
			_, err = stream.ReadFrom(src)
		} else {
			_, err = io.Copy(dst, src)
		}
		if err != nil {
			_ = dst.Close()
			_ = src.Close()
			return
		}
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go copyHalf(visitor, data.Conn)
	go copyHalf(data.Conn, visitor)
	wg.Wait()
}

// Watch retains the last parsed configuration and retries listener failures.
func (g *Gateway) Watch(path string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var c Config
			c, err = Parse(data)
			if err == nil {
				err = g.Apply(c)
			}
		}
		if err != nil {
			log.Printf("gateway config: %v", err)
		}
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
