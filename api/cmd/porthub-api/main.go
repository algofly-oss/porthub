// porthub-api is the PortHub server API: every route, the Socket.IO server,
// the firewall service and the background workers in one process.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/algofly-oss/porthub/api/internal/auth"
	"github.com/algofly-oss/porthub/api/internal/config"
	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/firewall"
	"github.com/algofly-oss/porthub/api/internal/gateway"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/realtime"
	"github.com/algofly-oss/porthub/api/internal/routes/access"
	"github.com/algofly-oss/porthub/api/internal/routes/account"
	"github.com/algofly-oss/porthub/api/internal/routes/connections"
	"github.com/algofly-oss/porthub/api/internal/routes/downloads"
	"github.com/algofly-oss/porthub/api/internal/routes/groups"
	"github.com/algofly-oss/porthub/api/internal/routes/machines"
	"github.com/algofly-oss/porthub/api/internal/routes/trafficroutes"
	"github.com/algofly-oss/porthub/api/internal/store"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "clients" {
		if err := runClients(os.Args[2:], os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		if err := runAudit(os.Args[2:], os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "init-db" {
		if err := initDB(); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	// The firewall service (nftables port policies) runs in this process on
	// its own loopback port; the API reaches it at FIREWALL_BASE_URL.
	if os.Getenv("FW_PORT") != "" {
		go func() {
			if err := firewall.Serve(ctx); err != nil {
				log.Fatalf("firewall: %v", err)
			}
		}()
	}
	db, closeDB, err := store.Connect(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		log.Fatal(err)
	}
	defer closeDB()
	server, err := httpapi.New()
	if err != nil {
		log.Fatal(err)
	}
	sessions := &auth.Sessions{DB: db, Cookie: cfg.SessionCookie}
	app := &core.App{DB: db, Cfg: cfg, Sessions: sessions}
	hub := registerAPI(server, app)

	if err := machines.EnsureDefaultPrivateNetworks(ctx, app); err != nil {
		log.Printf("Default private enrollment migration: %v", err)
	}
	startWorkers(ctx, app, hub)
	if err := app.WriteGatewayTrafficConfig(); err != nil {
		log.Fatalf("gateway public routing: %v", err)
	}
	if os.Getenv("PORTHUB_TUNNEL_GATEWAY_ENABLED") != "false" {
		gate := gateway.New(ctx)
		defer gate.Close()
		server.Mux.HandleFunc("/api/tunnel", gate.Handler)
		go gate.Watch(cfg.RatholeConfigPath)
		// Explicit migration-only fallback; no separate agent port by default.
		if addr := os.Getenv("PORTHUB_TUNNEL_LEGACY_LISTEN"); addr != "" {
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatal(err)
			}
			go func() { _ = gate.ServeLegacy(listener) }()
			log.Printf("Temporary legacy tunnel listener: %s", addr)
		}
	}

	httpServer := &http.Server{Addr: cfg.Listen, Handler: cors(sessions.RenewMiddleware(server.Mux)), ReadHeaderTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	log.Printf("PortHub API listening on %s", cfg.Listen)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// registerAPI assembles all routes together; tests exercise this exact wiring.
func registerAPI(server *httpapi.Server, app *core.App) *realtime.Hub {
	hub := realtime.New(app)
	server.Mux.Handle("/socket.io/", hub.Handler())

	auth.Register(server.API, &auth.Handlers{DB: app.DB, Config: app.Cfg, Sessions: app.Sessions})
	account.Register(server.API, app)
	machines.Register(server.API, app)
	connections.Register(server.API, app)
	groups.Register(server.API, app)
	trafficroutes.Register(server.API, app)
	access.Register(server.API, app)
	downloads.Register(server.API, app)
	downloads.Mount(server.Mux, app)

	return hub
}

// cors mirrors FastAPI's CORSMiddleware(allow_origins=["*"], credentials).
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || strings.HasPrefix(r.URL.Path, "/socket.io/") {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT")
			if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
				h.Set("Access-Control-Allow-Headers", req)
			}
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// retry runs fn after each delay until it succeeds.
func retry(ctx context.Context, name string, delays []time.Duration, fn func() (bool, error)) bool {
	for i, d := range delays {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
		}
		ok, err := fn()
		if err != nil {
			log.Printf("%s attempt %d failed: %v", name, i+1, err)
			continue
		}
		if ok {
			return true
		}
		log.Printf("%s attempt %d incomplete", name, i+1)
	}
	return false
}

func seconds(values ...int) []time.Duration {
	out := make([]time.Duration, len(values))
	for i, v := range values {
		out[i] = time.Duration(v) * time.Second
	}
	return out
}

// startWorkers mirrors the Python API's startup handler.
func startWorkers(ctx context.Context, app *core.App, hub *realtime.Hub) {
	indexes := []struct {
		coll  string
		model mongo.IndexModel
	}{
		{"user_sessions", mongo.IndexModel{Keys: bson.D{{Key: "user_id", Value: 1}}}},
		{"machine_status_events", mongo.IndexModel{Keys: bson.D{{Key: "machine_id", Value: 1}, {Key: "changed_at", Value: -1}}}},
		{"machine_status_events", mongo.IndexModel{Keys: bson.D{{Key: "changed_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(370 * 24 * 60 * 60)}},
	}
	for _, ix := range indexes {
		if _, err := app.C(ix.coll).Indexes().CreateOne(ctx, ix.model); err != nil {
			log.Printf("Failed to ensure %s index: %v", ix.coll, err)
		}
	}
	go trafficroutes.RunProxyActivity(ctx, app)

	rathole := func() (bool, error) {
		if err := app.RebuildServerTOML(ctx, false); err != nil {
			return false, err
		}
		content, err := os.ReadFile(app.Cfg.RatholeConfigPath)
		return err == nil && !core.IsDummyOnlyConfig(string(content)), err
	}
	if !retry(ctx, "Gateway configuration rebuild", seconds(0, 2, 5, 10, 20), rathole) {
		log.Printf("Continuing with empty gateway config; retrying in the background")
		go retry(ctx, "Gateway configuration rebuild", seconds(30, 60, 120), rathole)
	}
	if err := app.RebuildTrafficConfig(ctx); err != nil {
		log.Printf("Failed to rebuild Traefik traffic config during startup: %v", err)
		if err := app.WriteBaseTrafficConfig(); err != nil {
			log.Printf("Failed to write bootstrap Traefik traffic config: %v", err)
		}
		go retry(ctx, "Traefik traffic config rebuild", seconds(30, 60, 120), func() (bool, error) {
			return true, app.RebuildTrafficConfig(ctx)
		})
	}

	if err := hub.InitStatusCache(ctx); err != nil {
		log.Printf("machine status cache: %v", err)
	}
	if err := app.MarkOfflineMachinesAlerted(ctx); err != nil {
		log.Printf("mark offline machines alerted: %v", err)
	}
	go hub.RunStatusMonitor(ctx)
	go retry(ctx, "Firewall reconcile", seconds(0, 2, 5, 10, 20), func() (bool, error) {
		return true, app.ReconcileFirewall(ctx)
	})
	go connections.RunAutoRefresh(ctx, app)
	go app.RunOfflineDigest(ctx)
}
