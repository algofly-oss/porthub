package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
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
	Name          string
	Token         string `toml:"token"`
	LocalAddr     string `toml:"local_addr"`
	Type          string `toml:"type"`
	Nodelay       *bool  `toml:"nodelay"`
	RetryInterval int    `toml:"retry_interval"`
}
type Config struct {
	RemoteAddr       string
	HeartbeatTimeout time.Duration
	Services         map[string]Service
}

// ParseConfig reads the client section of a rathole TOML file, the format
// PortHub already renders in api/shared/machine_client.py.
func ParseConfig(data []byte) (Config, error) {
	var raw struct {
		Client struct {
			RemoteAddr       string                `toml:"remote_addr"`
			DefaultToken     string                `toml:"default_token"`
			HeartbeatTimeout *int                  `toml:"heartbeat_timeout"`
			RetryInterval    int                   `toml:"retry_interval"`
			Transport        struct{ Type string } `toml:"transport"`
			Services         map[string]Service    `toml:"services"`
		} `toml:"client"`
	}
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return Config{}, err
	}
	c := Config{RemoteAddr: raw.Client.RemoteAddr, HeartbeatTimeout: defaultHeartbeatTimeout, Services: map[string]Service{}}
	if t := raw.Client.Transport.Type; t != "" && t != "tcp" {
		return c, fmt.Errorf("transport %q is not supported; only tcp", t)
	}
	if _, _, err := net.SplitHostPort(c.RemoteAddr); err != nil {
		return c, fmt.Errorf("client.remote_addr: %w", err)
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
	return fmt.Sprintf("%s|%s|%s|%s|%v|%d|%s", remote, heartbeat, s.Token, s.LocalAddr, s.Nodelay, s.RetryInterval, s.Type)
}

// Apply starts, restarts or stops services so the running set matches c.
func (cl *Client) Apply(ctx context.Context, c Config) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for name, ch := range cl.running {
		s, ok := c.Services[name]
		if !ok || identity(c.RemoteAddr, c.HeartbeatTimeout, s) != ch.key {
			ch.cancel()
			<-ch.done
			delete(cl.running, name)
		}
	}
	for name, s := range c.Services {
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
	conn, err := cl.dialer(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(nodelay)
	}
	return conn, nil
}

func (cl *Client) control(ctx context.Context, remote string, heartbeat time.Duration, s Service) error {
	conn, err := cl.dial(ctx, remote, true)
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
	cl.logger.Printf("%s: control channel established", s.Name)
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
		if conn, err = cl.dial(ctx, remote, nodelay); err == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(budget) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err = conn.Write(encodeHello(helloData, session)); err != nil {
		return err
	}
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
	stop := context.AfterFunc(ctx, func() { conn.Close(); local.Close() })
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
