// porthub-api is the Go PortHub server API. Routes not yet ported are passed
// to the Python API (PORTHUB_PYTHON_API_URL) unchanged.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/algofly-oss/porthub/server/internal/auth"
	"github.com/algofly-oss/porthub/server/internal/config"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	db, closeDB, err := store.Connect(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		log.Fatal(err)
	}
	defer closeDB()
	server, err := httpapi.New(cfg.PythonAPI)
	if err != nil {
		log.Fatal(err)
	}
	sessions := &auth.Sessions{DB: db, Cookie: cfg.SessionCookie}
	auth.Register(server.API, &auth.Handlers{DB: db, Config: cfg, Sessions: sessions})
	httpServer := &http.Server{Addr: cfg.Listen, Handler: sessions.RenewMiddleware(server.Mux), ReadHeaderTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	log.Printf("PortHub API listening on %s (unported routes -> %s)", cfg.Listen, cfg.PythonAPI)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
