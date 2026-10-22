package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Golden bytes: bincode 1 encoding of Hello::ControlChannelHello(1, digest).
func TestWireEncoding(t *testing.T) {
	d := sum([]byte("svc"))
	b := encodeHello(helloControl, d)
	if hex.EncodeToString(b[:5]) != "0000000001" || !bytes.Equal(b[5:], d[:]) || len(b) != 37 {
		t.Fatalf("hello encoding %x", b)
	}
	if hex.EncodeToString(encodeHello(helloData, d)[:5]) != "0100000001" {
		t.Fatal("data hello tag")
	}
	if hex.EncodeToString(encodeU32(cmdHeartBeat)) != "01000000" {
		t.Fatal("u32 tag")
	}
}

func TestParsePortHubConfig(t *testing.T) {
	c, err := ParseConfig([]byte(`# Managed by PortHub. Manual changes will be overwritten.
[client]
remote_addr = "porthub.example:2334"

[client.services.porthub_abc_8080]
token = "secret-token"
local_addr = "127.0.0.1:8080"
`))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Services["porthub_abc_8080"]
	if c.RemoteAddr != "porthub.example:2334" || s.Token != "secret-token" || s.LocalAddr != "127.0.0.1:8080" || s.Type != "tcp" || c.HeartbeatTimeout != 40*time.Second {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{`[client]
remote_addr = "x:1"
[client.transport]
type = "noise"`, `[client]
remote_addr = "x:1"
[client.services.a]
token = "t"
local_addr = "127.0.0.1:1"
type = "udp"`, `[client]
remote_addr = "nohostport"`} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Fatalf("accepted: %s", bad)
		}
	}
}

// fakeServer follows rathole's src/server.rs for the TCP transport.
type fakeServer struct {
	t        *testing.T
	control  net.Listener
	services map[digest]string // service digest -> token
	mu       sync.Mutex
	sessions map[digest]net.Conn // session key -> control connection
	pending  map[digest]chan net.Conn
}

func newFakeServer(t *testing.T, services map[string]string) *fakeServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, control: l, services: map[digest]string{}, sessions: map[digest]net.Conn{}, pending: map[digest]chan net.Conn{}}
	for name, token := range services {
		s.services[sum([]byte(name))] = token
	}
	go s.accept()
	return s
}
func (s *fakeServer) accept() {
	for {
		conn, err := s.control.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}
func (s *fakeServer) handle(conn net.Conn) {
	kind, d, err := readHello(conn)
	if err != nil {
		conn.Close()
		return
	}
	if kind == helloData {
		s.mu.Lock()
		ch := s.pending[d]
		s.mu.Unlock()
		if ch == nil {
			conn.Close()
			return
		}
		ch <- conn
		return
	}
	token, ok := s.services[d]
	if !ok {
		conn.Write(encodeU32(ackServiceNotExist))
		conn.Close()
		return
	}
	var nonce digest
	rand.Read(nonce[:])
	conn.Write(encodeHello(helloControl, nonce))
	var auth digest
	if _, err := io.ReadFull(conn, auth[:]); err != nil || auth != sum([]byte(token), nonce[:]) {
		conn.Write(encodeU32(ackAuthFailed))
		conn.Close()
		return
	}
	conn.Write(encodeU32(ackOK))
	s.mu.Lock()
	s.sessions[auth] = conn
	s.pending[auth] = make(chan net.Conn, 16)
	s.mu.Unlock()
}

// visit simulates a public visitor arriving on the service's bind port.
func (s *fakeServer) visit(t *testing.T) net.Conn {
	t.Helper()
	var control net.Conn
	var pending chan net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for control == nil {
		s.mu.Lock()
		for k, c := range s.sessions {
			control, pending = c, s.pending[k]
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no control channel")
		}
		time.Sleep(20 * time.Millisecond)
	}
	control.Write(encodeU32(cmdHeartBeat))
	control.Write(encodeU32(cmdCreateDataChannel))
	select {
	case data := <-pending:
		data.Write(encodeU32(cmdStartForwardTCP))
		return data
	case <-time.After(5 * time.Second):
		t.Fatal("no data channel")
		return nil
	}
}

func echoServer(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c) // reads until the visitor half-closes
				c.Write(append([]byte("echo:"), b...))
			}()
		}
	}()
	return l
}

func TestForwardingWithHalfCloseAndReload(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()
	server := newFakeServer(t, map[string]string{"web": "token-1"})
	defer server.control.Close()
	var logs bytes.Buffer
	var logMu sync.Mutex
	client := New(log.New(writerFunc(func(b []byte) (int, error) { logMu.Lock(); defer logMu.Unlock(); return logs.Write(b) }), "", 0))
	defer client.Close()
	cfg := Config{RemoteAddr: server.control.Addr().String(), HeartbeatTimeout: 40 * time.Second, Services: map[string]Service{
		"web": {Name: "web", Token: "token-1", LocalAddr: echo.Addr().String(), Type: "tcp"},
	}}
	client.Apply(context.Background(), cfg)
	data := server.visit(t)
	payload := bytes.Repeat([]byte("x"), 1<<20)
	data.Write(payload)
	data.(*net.TCPConn).CloseWrite()
	got, _ := io.ReadAll(data)
	if !bytes.Equal(got, append([]byte("echo:"), payload...)) {
		t.Fatalf("forwarded %d bytes", len(got))
	}

	// Removing the service closes its control channel.
	client.Apply(context.Background(), Config{RemoteAddr: cfg.RemoteAddr, Services: map[string]Service{}})
	if len(client.Services()) != 0 {
		t.Fatal("service still running")
	}
}

func TestWrongTokenAndUnknownServiceRetry(t *testing.T) {
	server := newFakeServer(t, map[string]string{"web": "right"})
	defer server.control.Close()
	var mu sync.Mutex
	var logs strings.Builder
	client := New(log.New(writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.WriteString(string(b)) }), "", 0))
	client.Apply(context.Background(), Config{RemoteAddr: server.control.Addr().String(), Services: map[string]Service{
		"web":   {Name: "web", Token: "wrong", LocalAddr: "127.0.0.1:1", Type: "tcp"},
		"other": {Name: "other", Token: "x", LocalAddr: "127.0.0.1:1", Type: "tcp"},
	}})
	time.Sleep(2500 * time.Millisecond)
	client.Close()
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logs.String(), "web: incorrect token") || !strings.Contains(logs.String(), "other: service does not exist") {
		t.Fatal(logs.String())
	}
	if strings.Count(logs.String(), "web: incorrect token") < 2 {
		t.Fatal("client did not retry")
	}
}

func TestHeartbeatTimeoutReconnects(t *testing.T) {
	server := newFakeServer(t, map[string]string{"web": "t"})
	defer server.control.Close()
	var mu sync.Mutex
	var logs strings.Builder
	client := New(log.New(writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.WriteString(string(b)) }), "", 0))
	defer client.Close()
	client.Apply(context.Background(), Config{RemoteAddr: server.control.Addr().String(), HeartbeatTimeout: 300 * time.Millisecond, Services: map[string]Service{
		"web": {Name: "web", Token: "t", LocalAddr: "127.0.0.1:1", Type: "tcp"},
	}})
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logs.String(), "heartbeat timed out") || strings.Count(logs.String(), "control channel established") < 2 {
		t.Fatal(logs.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// Rathole keeps prewarmed data channels idle until a public visitor arrives.
// A handshake read deadline must not expire a valid pool entry during that wait.
type poolConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	waiting  chan time.Time
}

func (c *poolConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}
func (c *poolConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	select {
	case c.waiting <- d:
	default:
	}
	return c.Conn.Read(p)
}
func TestIdleDataPoolAndCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &poolConn{Conn: client, waiting: make(chan time.Time, 1)}
	cl := New(log.New(io.Discard, "", 0))
	cl.dialer = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cl.data(ctx, "gateway:2334", digest{}, Service{Name: "test"}) }()
	if _, _, err := readHello(server); err != nil {
		t.Fatal(err)
	}
	select {
	case deadline := <-conn.waiting:
		if !deadline.IsZero() {
			t.Fatal("idle pool channel has a read deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("client never waited for a visitor")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close idle data channel")
	}
}
