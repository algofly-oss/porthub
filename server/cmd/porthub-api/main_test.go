package main

import (
	"encoding/json"
	"github.com/algofly-oss/porthub/server/internal/auth"
	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCompleteAPIRegistration(t *testing.T) {
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	registerAPI(s, &core.App{Sessions: &auth.Sessions{Cookie: "session"}})
	for _, path := range []string{"/api/openapi.json", "/api/docs"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}

// This manifest was extracted from the original Python route decorators. It
// remains independent of Go registration, so removing a migrated route fails.
func TestEveryLegacyRouteIsImplementedInGo(t *testing.T) {
	raw, err := os.ReadFile("testdata/legacy_routes.json")
	if err != nil {
		t.Fatal(err)
	}
	var routes []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	registerAPI(s, &core.App{Sessions: &auth.Sessions{Cookie: "session"}})
	normalize := regexp.MustCompile(`\{[^}]+\}`)
	paths := map[string]bool{}
	for path, item := range s.API.OpenAPI().Paths {
		for method, exists := range map[string]bool{"GET": item.Get != nil, "POST": item.Post != nil, "PUT": item.Put != nil, "DELETE": item.Delete != nil, "PATCH": item.Patch != nil} {
			if exists {
				paths[method+" "+normalize.ReplaceAllString(path, "{}")] = true
			}
		}
	}
	if len(routes) < 80 {
		t.Fatal("legacy route manifest is incomplete")
	}
	for _, route := range routes {
		if !paths[route.Method+" "+normalize.ReplaceAllString(route.Path, "{}")] {
			t.Errorf("missing migrated route: %s %s", route.Method, route.Path)
		}
	}
}

func TestStandaloneAPIHasNoPythonFallback(t *testing.T) {
	t.Setenv("PORTHUB_PYTHON_API_URL", "http://127.0.0.1:1")
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/not-a-route", "/unported"} {
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 || strings.TrimSpace(w.Body.String()) != `{"detail":"Not Found"}` {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
