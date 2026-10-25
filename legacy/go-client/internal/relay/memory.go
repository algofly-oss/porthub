package relay

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pion/turn/v5"
)

// memoryNet gives TURN allocations in-process packet connections instead of
// loopback UDP sockets. Relayed traffic only ever flows between allocations of
// this relay, and kernel UDP buffers (which a container cannot enlarge)
// overflowed under bursts arriving from TCP, dropping packets that the TCP
// flows inside the tunnel then treated as congestion. Here a full queue makes
// the sender wait briefly instead, which back-pressures its WebSocket.
type memoryNet struct {
	mu    sync.Mutex
	next  int
	conns map[int]*memConn
}

const (
	memoryQueue     = 8192                  // packets per allocation
	memoryBlockTime = 50 * time.Millisecond // wait for a full queue before dropping
	firstPort       = 20000
	lastPort        = 65000
)

var errUnsupported = errors.New("only UDP relay allocations are supported")

func newMemoryNet() *memoryNet { return &memoryNet{next: firstPort, conns: map[int]*memConn{}} }

func (m *memoryNet) Validate() error { return nil }

func (m *memoryNet) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	port := conf.RequestedPort
	if port == 0 || m.conns[port] != nil {
		for tries := 0; ; tries++ {
			if tries > lastPort-firstPort {
				return nil, nil, errors.New("relay ports exhausted")
			}
			port = m.next
			m.next++
			if m.next > lastPort {
				m.next = firstPort
			}
			if m.conns[port] == nil {
				break
			}
		}
	}
	c := &memConn{net: m, port: port, addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		in: make(chan packet, memoryQueue), closed: make(chan struct{})}
	m.conns[port] = c
	return c, c.addr, nil
}

func (m *memoryNet) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errUnsupported
}

func (m *memoryNet) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	return nil, errUnsupported
}

func (m *memoryNet) lookup(port int) *memConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns[port]
}

type packet struct {
	data []byte
	from *net.UDPAddr
}

type memConn struct {
	net      *memoryNet
	port     int
	addr     *net.UDPAddr
	in       chan packet
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func (c *memConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case p := <-c.in:
		return copy(b, p.data), p.from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, timeoutError{}
	}
}

func (c *memConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok || !udp.IP.IsLoopback() {
		return len(b), nil // only allocations of this relay are reachable
	}
	target := c.net.lookup(udp.Port)
	if target == nil {
		return len(b), nil
	}
	p := packet{data: append([]byte(nil), b...), from: c.addr}
	select {
	case target.in <- p:
	default:
		timer := time.NewTimer(memoryBlockTime)
		defer timer.Stop()
		select {
		case target.in <- p:
		case <-target.closed:
		case <-timer.C: // persistently full: drop like a congested link
		}
	}
	return len(b), nil
}

func (c *memConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.net.mu.Lock()
		if c.net.conns[c.port] == c {
			delete(c.net.conns, c.port)
		}
		c.net.mu.Unlock()
	})
	return nil
}

func (c *memConn) LocalAddr() net.Addr { return c.addr }
func (c *memConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}
func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
