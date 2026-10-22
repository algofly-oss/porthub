package firewall

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// trafficWS is the unauthenticated /ports/traffic/ws stream: every second,
// each port's newest sample, sent only when there is one (ws_traffic). A
// minimal RFC 6455 server: text frames out; pings answered, close ends it.
func (s *Service) trafficWS(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		if !headerHas(r.Header, "Connection", "upgrade") || !headerHas(r.Header, "Upgrade", "websocket") || key == "" {
			notFound(w) // a plain HTTP request matches no route in Starlette
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "websocket unsupported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Time{})
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		if rw.Flush() != nil {
			return
		}

		var wmu sync.Mutex
		send := func(op byte, payload []byte) error {
			wmu.Lock()
			defer wmu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := conn.Write(frame(op, payload))
			return err
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			readFrames(rw.Reader, func(op byte, payload []byte) bool {
				switch op {
				case 0x8:
					_ = send(0x8, payload[:min(len(payload), 2)])
					return false
				case 0x9:
					_ = send(0xA, payload)
				}
				return true
			})
		}()

		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			if payload := s.latestData(time.Now().Unix()); len(payload.keys) > 0 {
				b, _ := json.Marshal(payload)
				if send(0x1, b) != nil {
					return
				}
			}
			select {
			case <-ctx.Done():
				_ = send(0x8, []byte{0x03, 0xE9}) // 1001 going away
				return
			case <-done:
				return
			case <-tick.C:
			}
		}
	}
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// frame builds one unmasked server frame with FIN set.
func frame(op byte, payload []byte) []byte {
	n := len(payload)
	head := []byte{0x80 | op}
	switch {
	case n < 126:
		head = append(head, byte(n))
	case n <= 0xFFFF:
		head = append(head, 126, byte(n>>8), byte(n))
	default:
		head = append(head, 127)
		head = binary.BigEndian.AppendUint64(head, uint64(n))
	}
	return append(head, payload...)
}

// readFrames reads client frames until an error or handle returns false.
func readFrames(r *bufio.Reader, handle func(op byte, payload []byte) bool) {
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		op := hdr[0] & 0x0F
		n := uint64(hdr[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > 1<<20 {
			return
		}
		var mask [4]byte
		masked := hdr[1]&0x80 != 0
		if masked {
			if _, err := io.ReadFull(r, mask[:]); err != nil {
				return
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		if !handle(op, payload) {
			return
		}
	}
}
