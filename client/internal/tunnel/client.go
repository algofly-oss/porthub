package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/algofly-oss/porthub/client/transport"
	"github.com/coder/websocket"
)

// Defaults mirror rathole's src/config.rs and src/transport/mod.rs.
const (
	defaultHeartbeatTimeout = 40 * time.Second
	defaultRetryInterval    = time.Second
	keepaliveIdle           = 20 * time.Second
	keepaliveInterval       = 8 * time.Second
	dialTimeout             = 10 * time.Second
)

type Service struct {
	PrimaryAddr                               string   `toml:"-"`
	DirectAddr, DirectFingerprint, DirectHost string   `toml:"-"`
	FallbackAddr                              string   `toml:"-"`
	FallbackAddrs                             []string `toml:"-"`
	Name                                      string
	Token                                     string `toml:"token"`
	LocalAddr                                 string `toml:"local_addr"`
	Type                                      string `toml:"type"`
	Nodelay                                   *bool  `toml:"nodelay"`
	RetryInterval                             int    `toml:"retry_interval"`
}
type Config struct {
	DirectAddr, DirectFingerprint, DirectHost string
	RemoteAddr                                string
	FallbackAddr                              string
	FallbackAddrs                             []string
	HeartbeatTimeout                          time.Duration
	Services                                  map[string]Service
}

// ParseConfig reads the client section of a rathole TOML file, the format
// PortHub renders in api/internal/core/machineclient.go.
func ParseConfig(data []byte) (Config, error) {
	var raw struct {
		Client struct {
			DirectHost        string                `toml:"direct_host"`
			DirectAddr        string                `toml:"direct_addr"`
			DirectFingerprint string                `toml:"direct_spki_sha256"`
			RemoteAddr        string                `toml:"remote_addr"`
			FallbackAddr      string                `toml:"fallback_addr"`
			FallbackAddrs     []string              `toml:"fallback_addrs"`
			DefaultToken      string                `toml:"default_token"`
			HeartbeatTimeout  *int                  `toml:"heartbeat_timeout"`
			RetryInterval     int                   `toml:"retry_interval"`
			Transport         struct{ Type string } `toml:"transport"`
			Services          map[string]Service    `toml:"services"`
		} `toml:"client"`
	}
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return Config{}, err
	}
	c := Config{RemoteAddr: raw.Client.RemoteAddr, FallbackAddr: raw.Client.FallbackAddr, FallbackAddrs: raw.Client.FallbackAddrs, HeartbeatTimeout: defaultHeartbeatTimeout, Services: map[string]Service{}}
	c.DirectAddr = raw.Client.DirectAddr
	c.DirectHost = raw.Client.DirectHost
	c.DirectFingerprint = raw.Client.DirectFingerprint
	if c.DirectAddr != "" {
		u, err := url.Parse(c.DirectAddr)
		pin, e := hex.DecodeString(c.DirectFingerprint)
		if err != nil || e != nil || len(pin) != 32 || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "wss") {
			return c, errors.New("direct HTTPS tunnel needs a valid URL and SHA-256 certificate key pin")
		}
	}
	if t := raw.Client.Transport.Type; t != "" && t != "tcp" {
		return c, fmt.Errorf("transport %q is not supported; only tcp", t)
	}
	if u, err := url.Parse(c.RemoteAddr); err == nil && (u.Scheme == "ws" || u.Scheme == "wss" || u.Scheme == "http" || u.Scheme == "https") {
		if u.Host == "" || u.User != nil || u.Fragment != "" {
			return c, errors.New("invalid tunnel URL")
		}
	} else if _, _, err := net.SplitHostPort(c.RemoteAddr); err != nil {
		return c, fmt.Errorf("client.remote_addr: %w", err)
	}
	for _, fallback := range append(append([]string{}, c.FallbackAddrs...), c.FallbackAddr) {
		if fallback == "" {
			continue
		}
		u, err := url.Parse(fallback)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "ws" && u.Scheme != "https" && u.Scheme != "wss") {
			return c, errors.New("fallback address must be an HTTP or HTTPS tunnel URL")
		}
	}
	if raw.Client.HeartbeatTimeout != nil {
		c.HeartbeatTimeout = time.Duration(*raw.Client.HeartbeatTimeout) * time.Second
	}
	for name, s := range raw.Client.Services {
		s.Name = name
		if s.Token == "" {
			s.Token = raw.Client.DefaultToken
		}
		if s.Type == "" {
			s.Type = "tcp"
		}
		if s.RetryInterval == 0 {
			s.RetryInterval = raw.Client.RetryInterval
		}
		if s.Token == "" || s.LocalAddr == "" {
			return c, fmt.Errorf("service %s needs token and local_addr", name)
		}
		if s.Type != "tcp" {
			return c, fmt.Errorf("service %s: type %q is not supported yet", name, s.Type)
		}
		c.Services[name] = s
	}
	return c, nil
}

// Client keeps one control channel per service, like rathole's client, and
// applies configuration changes by restarting only the services that changed.
type Client struct {
	mu      sync.Mutex
	running map[string]*channel
	logger  *log.Logger
	dialer  func(ctx context.Context, network, address string) (net.Conn, error)
}
type channel struct {
	key    string
	cancel context.CancelFunc
	done   chan struct{}
}

func New(logger *log.Logger) *Client {
	if logger == nil {
		logger = log.New(os.Stderr, "[porthub-tunnel] ", log.LstdFlags)
	}
	d := &net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepaliveIdle, Interval: keepaliveInterval, Count: 3}}
	return &Client{running: map[string]*channel{}, logger: logger, dialer: d.DialContext}
}

func identity(remote string, heartbeat time.Duration, s Service) string {
	nodelay := s.Nodelay == nil || *s.Nodelay
	return fmt.Sprintf("%s|%s|%s|%s|%v|%d|%s|%s", remote, heartbeat, s.Token, s.LocalAddr, nodelay, s.RetryInterval, s.Type, s.FallbackAddr+"|"+strings.Join(s.FallbackAddrs, ",")+"|"+s.DirectAddr+"|"+s.DirectFingerprint+"|"+s.DirectHost)
}

// Apply starts, restarts or stops services so the running set matches c.
func (cl *Client) Apply(ctx context.Context, c Config) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for name, ch := range cl.running {
		s, ok := c.Services[name]
		s.FallbackAddr = c.FallbackAddr
		s.PrimaryAddr = c.RemoteAddr
		s.DirectAddr = c.DirectAddr
		s.DirectHost = c.DirectHost
		s.DirectFingerprint = c.DirectFingerprint
		s.FallbackAddrs = c.FallbackAddrs
		if !ok || identity(c.RemoteAddr, c.HeartbeatTimeout, s) != ch.key {
			ch.cancel()
			<-ch.done
			delete(cl.running, name)
		}
	}
	for name, s := range c.Services {
		s.FallbackAddr = c.FallbackAddr
		s.PrimaryAddr = c.RemoteAddr
		s.DirectAddr = c.DirectAddr
		s.DirectHost = c.DirectHost
		s.DirectFingerprint = c.DirectFingerprint
		s.FallbackAddrs = c.FallbackAddrs
		if _, ok := cl.running[name]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(ctx)
		ch := &channel{key: identity(c.RemoteAddr, c.HeartbeatTimeout, s), cancel: cancel, done: make(chan struct{})}
		cl.running[name] = ch
		go func() {
			defer close(ch.done)
			cl.supervise(ctx, c.RemoteAddr, c.HeartbeatTimeout, s)
		}()
	}
}

// Services returns the names of running services, sorted.
func (cl *Client) Services() []string {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	var names []string
	for name := range cl.running {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Close stops every service and waits for their control channels to exit.
func (cl *Client) Close() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for name, ch := range cl.running {
		ch.cancel()
		<-ch.done
		delete(cl.running, name)
	}
}

// supervise reconnects with rathole's control-channel backoff: exponential
// (x3, ±20% jitter) capped at the retry interval, reset after a stable run.
func (cl *Client) supervise(ctx context.Context, remote string, heartbeat time.Duration, s Service) {
	limit := defaultRetryInterval
	if s.RetryInterval > 0 {
		limit = time.Duration(s.RetryInterval) * time.Second
	}
	delay := 500 * time.Millisecond
	for {
		started := time.Now()
		err := cl.control(ctx, remote, heartbeat, s)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > 3*time.Second {
			delay = 500 * time.Millisecond
		}
		wait := min(time.Duration(float64(delay)*(0.8+0.4*rand.Float64())), limit)
		cl.logger.Printf("%s: %v; retry in %v", s.Name, err, wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		delay = min(delay*3, limit)
	}
}

func (cl *Client) dial(ctx context.Context, address string, nodelay bool) (net.Conn, error) {
	return cl.dialPinned(ctx, address, nodelay, "")
}

var tlsSessions = tls.NewLRUClientSessionCache(256)

func (cl *Client) dialPinned(ctx context.Context, address string, nodelay bool, pin string, hosts ...string) (net.Conn, error) {
	if u, err := url.Parse(address); err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "ws" || u.Scheme == "wss") {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		opts := &websocket.DialOptions{Subprotocols: []string{transport.Subprotocol}, CompressionMode: websocket.CompressionDisabled}
		if pin != "" {
			if u.Scheme != "https" && u.Scheme != "wss" {
				return nil, errors.New("certificate pin requires HTTPS")
			}
			expected, e := hex.DecodeString(pin)
			if e != nil || len(expected) != 32 {
				return nil, errors.New("invalid tunnel certificate key pin")
			}
			t := http.DefaultTransport.(*http.Transport).Clone()
			t.ForceAttemptHTTP2 = false
			if len(hosts) > 0 && hosts[0] != "" {
				opts.Host = hosts[0]
			}
			// The authenticated API supplies the origin's key pin. Verify it
			// on every handshake (including resumed sessions) instead of CA/DNS
			// validation; a changed key must never be silently accepted.
			serverName := ""
			if h, e := url.Parse("https://" + opts.Host); e == nil {
				serverName = h.Hostname()
			}
			t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, NextProtos: []string{"http/1.1"}, ClientSessionCache: tlsSessions, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("missing tunnel certificate")
				}
				got := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(expected, got[:]) != 1 {
					return errors.New("tunnel certificate key pin mismatch")
				}
				return nil
			}}
			opts.HTTPClient = &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			if stream, err := transport.DialUpgrade(dialCtx, opts.HTTPClient, address, opts.Host); err == nil {
				return stream, nil
			}
		}
		if pin == "" && (u.Scheme == "http" || u.Scheme == "ws") {
			client := &http.Client{Transport: http.DefaultTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			if stream, err := transport.DialUpgrade(dialCtx, client, address, ""); err == nil {
				return stream, nil
			}
		}
		ws, _, err := websocket.Dial(dialCtx, address, opts)
		if err != nil {
			return nil, err
		}
		if ws.Subprotocol() != transport.Subprotocol {
			_ = ws.CloseNow()
			return nil, errors.New("tunnel subprotocol was not accepted")
		}
		return transport.New(ws), nil
	}
	conn, err := cl.dialer(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(nodelay)
	}
	return conn, nil
}

func (cl *Client) dialTunnel(ctx context.Context, remote string, s Service) (net.Conn, error) {
	pin := ""
	if remote == s.DirectAddr {
		pin = s.DirectFingerprint
	}
	nodelay := s.Nodelay == nil || *s.Nodelay
	return cl.dialPinned(ctx, remote, nodelay, pin, s.DirectHost)
}

// Data channels share the authenticated session across the API listeners.
// If an origin certificate rotates before the next configuration sync, use
// the canonical HTTPS endpoint while waiting for the updated key pin.
func (cl *Client) dialData(ctx context.Context, remote string, s Service) (net.Conn, error) {
	conn, err := cl.dialTunnel(ctx, remote, s)
	if err == nil || remote != s.DirectAddr || s.PrimaryAddr == "" || ctx.Err() != nil {
		return conn, err
	}
	for _, endpoint := range append([]string{s.PrimaryAddr}, s.FallbackAddrs...) {
		conn, err = cl.dialTunnel(ctx, endpoint, s)
		if err == nil || ctx.Err() != nil {
			return conn, err
		}
	}
	return nil, err
}

func (cl *Client) control(ctx context.Context, remote string, heartbeat time.Duration, s Service) error {
	var conn net.Conn
	var err error
	if s.DirectAddr != "" {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err = cl.dialTunnel(attempt, s.DirectAddr, s)
		cancel()
		if err == nil {
			remote = s.DirectAddr
		}
	}
	if conn == nil {
		conn, err = cl.dialTunnel(ctx, remote, s)
	}
	for _, fallback := range append(append([]string{}, s.FallbackAddrs...), s.FallbackAddr) {
		if err == nil || ctx.Err() != nil {
			break
		}
		if fallback == "" {
			continue
		}
		remote = fallback
		conn, err = cl.dialTunnel(ctx, remote, s)
		if err == nil {
			cl.logger.Printf("%s: using fallback %s", s.Name, remote)
		}
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err = conn.Write(encodeHello(helloControl, sum([]byte(s.Name)))); err != nil {
		return err
	}
	kind, nonce, err := readHello(conn)
	if err != nil {
		return err
	}
	if kind != helloControl {
		return errors.New("unexpected hello from server")
	}
	session := sum([]byte(s.Token), nonce[:])
	if _, err = conn.Write(session[:]); err != nil {
		return err
	}
	ack, err := readU32(conn)
	if err != nil {
		return fmt.Errorf("read acknowledgement: %w", err)
	}
	if ack != ackOK {
		return AuthError{ack}
	}
	protocol := "tcp"
	if stream, ok := conn.(interface{ Protocol() string }); ok {
		protocol = stream.Protocol()
	}
	cl.logger.Printf("%s: control channel established via %s (%s)", s.Name, remote, protocol)
	for {
		deadline := time.Time{}
		if heartbeat > 0 {
			deadline = time.Now().Add(heartbeat)
		}
		_ = conn.SetReadDeadline(deadline)
		cmd, err := readU32(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				return errors.New("heartbeat timed out")
			}
			return err
		}
		switch cmd {
		case cmdCreateDataChannel:
			go func() {
				if err := cl.data(ctx, remote, session, s); err != nil && ctx.Err() == nil {
					cl.logger.Printf("%s: data channel: %v", s.Name, err)
				}
			}()
		case cmdHeartBeat:
		default:
			return fmt.Errorf("unknown control command %d", cmd)
		}
	}
}

// data opens one data channel for one visitor connection. The server waits
// for it, so dialing retries briefly (rathole: 100 ms steps, 10 s budget).
func (cl *Client) data(ctx context.Context, remote string, session digest, s Service) error {
	nodelay := s.Nodelay == nil || *s.Nodelay
	var conn net.Conn
	var err error
	budget := time.Now().Add(10 * time.Second)
	for {
		if conn, err = cl.dialData(ctx, remote, s); err == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(budget) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer conn.Close()
	stopRemote := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopRemote()
	_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
	if _, err = conn.Write(encodeHello(helloData, session)); err != nil {
		return err
	}
	// Rathole prewarms pooled data channels before a visitor arrives. They
	// may remain idle indefinitely; only the hello write has a deadline.
	_ = conn.SetDeadline(time.Time{})
	cmd, err := readU32(conn)
	if err != nil {
		return fmt.Errorf("read data command: %w", err)
	}
	if cmd == cmdStartForwardUDP {
		return errors.New("server requested UDP forwarding; this service is TCP")
	}
	if cmd != cmdStartForwardTCP {
		return fmt.Errorf("unknown data command %d", cmd)
	}
	_ = conn.SetDeadline(time.Time{})
	local, err := cl.dial(ctx, s.LocalAddr, nodelay)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", s.LocalAddr, err)
	}
	defer local.Close()
	stop := context.AfterFunc(ctx, func() { local.Close() })
	defer stop()
	pipe(conn, local)
	return nil
}

// pipe copies both ways and propagates half-close, like tokio's
// copy_bidirectional, so request/response protocols that shut down one
// direction keep working.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	wg.Wait()
}
