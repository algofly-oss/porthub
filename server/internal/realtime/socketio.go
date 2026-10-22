// Package realtime is the Socket.IO server (api/shared/sockets.py): browser
// and machine connections, rooms, live machine status and log streaming.
//
// It speaks Engine.IO v4 / Socket.IO v5 over WebSocket only, which is what
// the web app uses (transports: ["websocket"]).
package realtime

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const (
	pingInterval = 25 * time.Second
	pingTimeout  = 20 * time.Second
	maxPayload   = 1000000
)

// conn is one Socket.IO client on the default namespace.
type conn struct {
	sid  string
	send chan []byte
	once sync.Once
	done chan struct{}

	mu      sync.Mutex
	session map[string]string
}

func (c *conn) get(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session[key]
}

func (c *conn) close() { c.once.Do(func() { close(c.done) }) }

func (c *conn) push(frame []byte) {
	select {
	case c.send <- frame:
	case <-c.done:
	}
}

// server tracks connections and rooms.
type server struct {
	mu    sync.RWMutex
	rooms map[string]map[*conn]bool
	bySID map[string]*conn

	// onConnect returns false to refuse the connection.
	onConnect    func(ctx context.Context, c *conn, r *http.Request, auth map[string]any) bool
	onEvent      func(ctx context.Context, c *conn, event string, data any)
	onDisconnect func(c *conn)
}

func newServer() *server {
	return &server{rooms: map[string]map[*conn]bool{}, bySID: map[string]*conn{}}
}

func (s *server) join(c *conn, room string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rooms[room] == nil {
		s.rooms[room] = map[*conn]bool{}
	}
	s.rooms[room][c] = true
}

func (s *server) leave(c *conn, room string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if members := s.rooms[room]; members != nil {
		delete(members, c)
		if len(members) == 0 {
			delete(s.rooms, room)
		}
	}
}

func (s *server) leaveAll(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for room, members := range s.rooms {
		delete(members, c)
		if len(members) == 0 {
			delete(s.rooms, room)
		}
	}
	delete(s.bySID, c.sid)
}

// emit sends an event to every connection in room (a sid is its own room).
func (s *server) emit(event string, data any, room string) {
	payload, err := json.Marshal([]any{event, data})
	if err != nil {
		log.Printf("socket.io: encode %s: %v", event, err)
		return
	}
	frame := append([]byte("42"), payload...)
	s.mu.RLock()
	targets := make([]*conn, 0, len(s.rooms[room]))
	for c := range s.rooms[room] {
		targets = append(targets, c)
	}
	s.mu.RUnlock()
	for _, c := range targets {
		select {
		case c.send <- frame:
		case <-c.done:
		default:
			log.Printf("socket.io: dropping slow client %s", c.sid)
			c.close()
		}
	}
}

func (s *server) disconnect(sid string) {
	s.mu.RLock()
	c := s.bySID[sid]
	s.mu.RUnlock()
	if c != nil {
		select {
		case c.send <- []byte("41"):
		default:
		}
		time.AfterFunc(100*time.Millisecond, c.close)
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("EIO") != "4" || q.Get("transport") != "websocket" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":3,"message":"Bad request"}`))
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ws.SetReadLimit(maxPayload)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &conn{sid: uuid.NewString(), send: make(chan []byte, 256), done: make(chan struct{}), session: map[string]string{}}
	open, _ := json.Marshal(map[string]any{"sid": strings.ReplaceAll(uuid.NewString(), "-", "")[:20], "upgrades": []string{},
		"pingInterval": pingInterval.Milliseconds(), "pingTimeout": pingTimeout.Milliseconds(), "maxPayload": maxPayload})
	if err := ws.Write(ctx, websocket.MessageText, append([]byte("0"), open...)); err != nil {
		return
	}
	connected := false
	defer func() {
		c.close()
		if connected && s.onDisconnect != nil {
			s.onDisconnect(c)
		}
		s.leaveAll(c)
		_ = ws.CloseNow()
	}()

	// writer and heartbeat
	pong := make(chan struct{}, 1)
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				cancel()
				return
			case frame := <-c.send:
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Write(wctx, websocket.MessageText, frame)
				wcancel()
				if err != nil {
					c.close()
				}
			case <-ticker.C:
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Write(wctx, websocket.MessageText, []byte("2"))
				wcancel()
				if err != nil {
					c.close()
					continue
				}
				select {
				case <-pong:
				case <-c.done:
				case <-time.After(pingTimeout):
					c.close()
				}
			}
		}
	}()

	for {
		typ, msg, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText || len(msg) == 0 {
			continue
		}
		switch msg[0] {
		case '3': // pong
			select {
			case pong <- struct{}{}:
			default:
			}
		case '1': // close
			return
		case '4': // Socket.IO packet
			if len(msg) < 2 {
				continue
			}
			packet := msg[2:]
			// Only the default namespace is served.
			if len(packet) > 0 && packet[0] == '/' {
				ns := string(packet)
				if i := strings.IndexByte(ns, ','); i >= 0 {
					ns, packet = ns[:i], packet[i+1:]
				}
				if ns != "/" {
					if msg[1] == '0' {
						c.push([]byte(`44` + ns + `,{"message":"Invalid namespace"}`))
					}
					continue
				}
			}
			switch msg[1] {
			case '0': // CONNECT
				var auth map[string]any
				_ = json.Unmarshal(packet, &auth)
				s.mu.Lock()
				s.bySID[c.sid] = c
				s.mu.Unlock()
				s.join(c, c.sid)
				if s.onConnect != nil && !s.onConnect(ctx, c, r, auth) {
					c.push([]byte(`44{"message":"Connection rejected by server"}`))
					continue
				}
				connected = true
				ack, _ := json.Marshal(map[string]string{"sid": c.sid})
				c.push(append([]byte("40"), ack...))
				s.emit("join", map[string]string{"sid": c.sid}, c.sid)
			case '1': // DISCONNECT
				return
			case '2': // EVENT (acks are not used by PortHub)
				if !connected {
					continue
				}
				for len(packet) > 0 && packet[0] >= '0' && packet[0] <= '9' {
					packet = packet[1:]
				}
				var args []json.RawMessage
				if json.Unmarshal(packet, &args) != nil || len(args) == 0 {
					continue
				}
				var event string
				if json.Unmarshal(args[0], &event) != nil {
					continue
				}
				var data any
				if len(args) > 1 {
					_ = json.Unmarshal(args[1], &data)
				}
				if s.onEvent != nil {
					s.onEvent(ctx, c, event, data)
				}
			}
		}
	}
}
