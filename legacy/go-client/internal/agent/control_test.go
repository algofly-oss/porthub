package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlFallbackPersistsAndKeepsIdentity(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"snapshot": map[string]any{"workspace": "workspace", "self": "peer"}, "control_fallback_urls": []string{server.URL}})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "profile.json")
	cfg := Config{Server: "https://127.0.0.1:1", PeerID: "peer", Workspace: "workspace", Token: strings.Repeat("t", 32), FallbackServers: []string{server.URL}}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewControl(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Start with a different list so the authenticated response updates disk.
	control.config.FallbackServers = append(control.config.FallbackServers, "http://127.0.0.1:2")
	if _, err = control.sync(context.Background(), syncRequest{}); err != nil {
		t.Fatal(err)
	}
	saved, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.FallbackServers) != 1 || saved.FallbackServers[0] != server.URL {
		t.Fatal("fallback profile was not persisted")
	}
	if saved.Server != cfg.Server || saved.Token != cfg.Token {
		t.Fatal("canonical identity changed")
	}
}

func TestControlNeverRetriesRevocation(t *testing.T) {
	fallbackCalls := 0
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fallbackCalls++; w.WriteHeader(200) }))
	defer fallback.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer primary.Close()
	c, err := NewControl(Config{Server: primary.URL, AllowInsecureHTTP: true, FallbackServers: []string{fallback.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.sync(context.Background(), syncRequest{}); err == nil {
		t.Fatal("accepted a revoked peer")
	}
	if fallbackCalls != 0 {
		t.Fatal("revocation retried on another endpoint")
	}
}
