// Package transport carries a TCP byte stream over the existing API WebSocket.
// A one-byte envelope preserves TCP half-close without closing the return path.
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const Path = "/api/tunnel"
const Subprotocol = "porthub.tcp.v1"
const frameSize = 64 * 1024
const directFrameSize = 1024 * 1024

var frames = sync.Pool{New: func() any { b := make([]byte, frameSize+5); return &b }}
var copyBuffers = sync.Pool{New: func() any { b := make([]byte, 256*1024); return &b }}

type Stream struct {
	net.Conn          // NetConn supplies addresses and cancellable deadline support.
	ws                *websocket.Conn
	reader            *io.LimitedReader
	readMu, writeMu   sync.Mutex
	readEOF, writeEOF bool
}

func New(ws *websocket.Conn) *Stream {
	c := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	ws.SetReadLimit(frameSize + 5)
	return &Stream{Conn: c, ws: ws}
}

// Wrap carries the same framed stream over a direct HTTP Upgrade connection.
func Wrap(conn net.Conn) *Stream { return &Stream{Conn: conn} }

func (s *Stream) Protocol() string {
	if s.ws == nil {
		return "http-upgrade"
	}
	return "websocket"
}

// Deadlines apply to the framed stream through NetConn. Framing uses NetConn's
// byte stream rather than a second reader, so its cancellation remains effective.
func (s *Stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if s.readEOF {
		return 0, io.EOF
	}
	for {
		if s.reader != nil {
			n, err := s.reader.Read(p)
			if err == io.EOF {
				s.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}
		length, err := s.nextFrame()
		if err != nil {
			return 0, err
		}
		s.reader = &io.LimitedReader{R: s.Conn, N: int64(length)}
	}
}

func (s *Stream) nextFrame() (int, error) {
	for {
		var header [5]byte
		if _, err := io.ReadFull(s.Conn, header[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint32(header[1:]))
		if header[0] == 2 && n == 0 {
			continue
		}
		if header[0] == 1 && n == 0 {
			s.readEOF = true
			return 0, io.EOF
		}
		limit := frameSize
		if s.ws == nil {
			limit = directFrameSize
		}
		if header[0] != 0 || n == 0 || n > limit {
			return 0, errors.New("invalid tunnel frame")
		}
		return n, nil
	}
}

// WriteTo lets Linux splice framed payloads from the API's plain TCP backend
// into the public socket. TLS remains at the existing reverse proxy listener.
func (s *Stream) WriteTo(dst io.Writer) (int64, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var total int64
	for {
		if s.readEOF {
			return total, nil
		}
		if s.reader == nil {
			n, err := s.nextFrame()
			if err == io.EOF {
				return total, nil
			}
			if err != nil {
				return total, err
			}
			s.reader = &io.LimitedReader{R: s.Conn, N: int64(n)}
		}
		n, err := io.Copy(dst, s.reader)
		total += n
		if err != nil {
			return total, err
		}
		if s.reader.N != 0 {
			return total, io.ErrUnexpectedEOF
		}
		s.reader = nil
	}
}

// ReadFrom uses larger reads for bulk traffic without waiting to fill a block.
func (s *Stream) ReadFrom(src io.Reader) (int64, error) {
	buffer := copyBuffers.Get().(*[]byte)
	defer copyBuffers.Put(buffer)
	var total int64
	for {
		n, err := src.Read(*buffer)
		if n > 0 {
			written, e := s.Write((*buffer)[:n])
			total += int64(written)
			if e != nil {
				return total, e
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (s *Stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEOF {
		return 0, net.ErrClosed
	}
	total := 0
	if tcp, ok := s.Conn.(*net.TCPConn); ok && s.ws == nil {
		for len(p) > 0 {
			n := min(len(p), directFrameSize)
			var header [5]byte
			binary.BigEndian.PutUint32(header[1:], uint32(n))
			buffers := net.Buffers{header[:], p[:n]}
			written, err := buffers.WriteTo(tcp)
			total += max(0, int(written)-len(header))
			if err != nil {
				return total, err
			}
			p = p[n:]
		}
		return total, nil
	}
	buffer := frames.Get().(*[]byte)
	defer frames.Put(buffer)
	for len(p) > 0 {
		n := min(len(p), frameSize)
		// One WebSocket write per frame; no compression or extra flush round trips.
		frame := (*buffer)[:5+n]
		frame[0] = 0
		frame[1] = byte(n >> 24)
		frame[2] = byte(n >> 16)
		frame[3] = byte(n >> 8)
		frame[4] = byte(n)
		copy(frame[5:], p[:n])
		if _, err := s.Conn.Write(frame); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEOF {
		return nil
	}
	s.writeEOF = true
	_, err := s.Conn.Write([]byte{1, 0, 0, 0, 0})
	return err
}

func (s *Stream) Close() error {
	if s.ws != nil {
		return s.ws.CloseNow()
	}
	return s.Conn.Close()
}

// KeepAlive sends one-way framed heartbeats, including on idle pooled channels.
// Unlike WebSocket ping/pong this does not require an idle server-side reader.
func (s *Stream) KeepAlive(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.writeMu.Lock()
			_ = s.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := s.Conn.Write([]byte{2, 0, 0, 0, 0})
			_ = s.Conn.SetWriteDeadline(time.Time{})
			s.writeMu.Unlock()
			if err != nil {
				_ = s.Close()
				return
			}
		}
	}
}
