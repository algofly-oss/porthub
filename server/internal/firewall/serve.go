package firewall

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// Service holds the in-memory state of shared/state.py. One process owns the
// counter baselines and the SQLite writes (NUM_WORKERS = 1).
type Service struct {
	cfg   Config
	db    *sql.DB
	epoch time.Time

	mu      sync.Mutex // PORT_STATS, ACTIVE_PORTS, pending
	stats   map[int64]*portStat
	order   []int64 // PORT_STATS insertion order
	active  map[int64]int64
	pending []pendingRow

	polMu sync.Mutex // STATE and nft apply
	state map[int64]Policy
}

func newService(cfg Config) *Service {
	return &Service{cfg: cfg, epoch: time.Now(), stats: map[int64]*portStat{},
		active: map[int64]int64{}, state: map[int64]Policy{}}
}

// Serve runs the firewall service until ctx is done: schema migration, state
// restore, nft rules, sampler and db writer, and the HTTP API on
// FW_HOST:FW_PORT.
func Serve(ctx context.Context) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	s := newService(cfg)
	if s.db, err = openDB(cfg.DBPath); err != nil {
		return err
	}
	defer s.db.Close()
	if err = initDB(ctx, s.db); err != nil {
		return err
	}
	if s.state, err = loadState(ctx, s.db); err != nil {
		return err
	}
	if err = s.applyRules(s.state); err != nil {
		return err
	}

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.trafficLoop(loopCtx) }()
	go func() { defer wg.Done(); s.dbWriter(loopCtx) }()
	log.Printf("Firewall service started with %d persisted port policies", len(s.state))

	addr := net.JoinHostPort(cfg.Host, strconv.FormatInt(cfg.Port, 10))
	network := "tcp"
	if ip, err := netip.ParseAddr(cfg.Host); err == nil && ip.Is4() {
		network = "tcp4" // uvicorn binds 0.0.0.0 as IPv4 only
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		cancel()
		wg.Wait()
		return err
	}
	srv := &http.Server{Handler: s.Handler(loopCtx), ReadHeaderTimeout: 30 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		stop()
		err = nil
	case err = <-errc:
	}
	cancel()
	wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// dbWriter flushes pending samples, active ports and recent IPs (db_writer).
func (s *Service) dbWriter(ctx context.Context) {
	for {
		s.mu.Lock()
		if len(s.pending) == 0 {
			s.mu.Unlock()
			if !sleep(ctx, time.Second) {
				return
			}
			continue
		}
		batch := s.pending
		s.pending = nil
		var tracked []int64
		seen := map[int64]bool{}
		var recent []recentRow
		for _, r := range batch {
			if seen[r.port] {
				continue
			}
			seen[r.port] = true
			tracked = append(tracked, r.port)
			if st := s.stats[r.port]; st != nil {
				for _, h := range st.recentHits {
					recent = append(recent, recentRow{port: r.port, ip: h.IP, lastSeen: h.LastSeen})
				}
			}
		}
		s.mu.Unlock()
		pruneBefore := time.Now().Unix() - s.cfg.BufferSeconds
		if err := s.writeBatch(context.WithoutCancel(ctx), batch, recent, tracked, pruneBefore); err != nil {
			log.Printf("firewall: db writer: %v", err)
		}
		if !sleep(ctx, 5*time.Second) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Handler is the firewall HTTP API: huma routes, the traffic websocket,
// FastAPI-style 404/405 bodies and Starlette's CORS behaviour.
func (s *Service) Handler(ctx context.Context) http.Handler {
	root := s.cfg.APIRoot
	mux := http.NewServeMux()
	cfg := huma.DefaultConfig("PortHub Firewall API", "0.1.0")
	cfg.OpenAPIPath = root + "/openapi"
	cfg.DocsPath = root + "/docs"
	cfg.DocsRenderer = huma.DocsRendererSwaggerUI
	cfg.SchemasPath = root + "/schemas"
	cfg.CreateHooks = nil // no "$schema" links in bodies
	api := humago.New(mux, cfg)
	api.UseMiddleware(func(hctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(hctx)
		next(huma.WithValue(hctx, requestKey{}, r))
	})
	s.register(api)
	mux.HandleFunc("GET "+root+"/ports/traffic/ws", s.trafficWS(ctx))
	mux.HandleFunc("GET "+root, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", root+"/docs")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	return cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, pattern := mux.Handler(r); pattern == "" {
			rec := &statusRecorder{header: http.Header{}}
			h.ServeHTTP(rec, r)
			if rec.status == http.StatusMethodNotAllowed {
				writeJSONDetail(w, http.StatusMethodNotAllowed, "Method Not Allowed")
				return
			}
			notFound(w)
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func writeJSONDetail(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"detail":` + strconv.Quote(detail) + `}`))
}

func notFound(w http.ResponseWriter) { writeJSONDetail(w, http.StatusNotFound, "Not Found") }

type statusRecorder struct {
	header http.Header
	status int
}

func (r *statusRecorder) Header() http.Header         { return r.header }
func (r *statusRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *statusRecorder) WriteHeader(status int)      { r.status = status }

// cors mirrors Starlette 0.19 CORSMiddleware(allow_origins=["*"],
// allow_methods=["*"], allow_headers=["*"], allow_credentials=True).
func cors(next http.Handler) http.Handler {
	const methods = "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Values("Origin")
		if len(origin) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		if reqMethod := r.Header.Values("Access-Control-Request-Method"); r.Method == http.MethodOptions && len(reqMethod) > 0 {
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", methods)
			h.Set("Access-Control-Max-Age", "600")
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Origin", origin[0])
			if reqHeaders := r.Header.Values("Access-Control-Request-Headers"); len(reqHeaders) > 0 {
				h.Set("Access-Control-Allow-Headers", reqHeaders[0])
			}
			h.Set("Content-Type", "text/plain; charset=utf-8")
			if !strings.Contains(", "+methods+", ", ", "+reqMethod[0]+", ") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Disallowed CORS method"))
				return
			}
			_, _ = w.Write([]byte("OK"))
			return
		}
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		if len(r.Header.Values("Cookie")) > 0 {
			h.Set("Access-Control-Allow-Origin", origin[0])
			h.Add("Vary", "Origin")
		}
		next.ServeHTTP(w, r)
	})
}
