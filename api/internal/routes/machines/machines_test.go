package machines

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/algofly-oss/porthub/api/internal/auth"
	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func newServer(t *testing.T) *httpapi.Server {
	t.Helper()
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	app := &core.App{Sessions: &auth.Sessions{Cookie: "porthub_session"}}
	Register(s.API, app) // panics on conflicting mux patterns
	return s
}

func do(t *testing.T, s *httpapi.Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	return w
}

// Requests below fail before any database access.
func TestRoutes(t *testing.T) {
	s := newServer(t)
	cases := []struct {
		method, path, body string
		status             int
		contains           string
	}{
		// nulls and unknown fields are accepted like pydantic.
		{"POST", "/api/machines/client/auth", `{"machine_id":"bad","token":"x","hostname":null,"is_active":null,"extra":1}`, 400, "Invalid machine id"},
		{"POST", "/api/machines/client/auth", `{"machine_id":"bad","token":""}`, 422, "token"},
		{"POST", "/api/machines/client/logs", `{"machine_id":"bad","token":"x"}`, 400, "Invalid machine id"},
		{"POST", "/api/machines/client/deletion-ack", `{"machine_id":"bad","token":"x"}`, 400, "Invalid machine id"},
		{"POST", "/api/machines/sync", `{"machine_id":"bad","token":"x","public_ip":null}`, 400, "Invalid machine id"},
		{"GET", "/api/machines/client/changes.toml?machine_id=bad&token=x&since=v", "", 400, "Invalid machine id"},
		{"GET", "/api/machines/client/changes?machine_id=bad&token=x&since=v&wait_seconds=0", "", 422, "wait_seconds"},
		{"GET", "/api/machines/client/changes?machine_id=bad&token=x", "", 422, "since"},
		{"GET", "/api/machines/client/config.toml?machine_id=bad&token=x", "", 400, "Invalid machine id"},
		{"GET", "/api/machines/bad/tok/downloads/rathole/x86_64", "", 400, "Invalid machine id"},
		{"GET", "/api/machines/bad/tok/install.sh", "", 400, "Invalid machine id"},
		{"GET", "/api/machines/list", "", 400, "User not logged in"},
		{"PUT", "/api/machines/update", `{"name":"a","group_ids":null,"client_setup_service_domain":null}`, 400, "User not logged in"},
		{"POST", "/api/machines/add", `{"name":""}`, 422, "name"},
		// shared /{first}/{second} route
		{"GET", "/api/machines/command/status-history?days=0", "", 422, "days"},
		{"GET", "/api/machines/abc/status-history", "", 400, "User not logged in"},
		{"GET", "/api/machines/command/abc?days=0", "", 400, "User not logged in"},
		{"GET", "/api/machines/abc/def", "", 404, `{"detail":"Not Found"}`},
	}
	for _, c := range cases {
		w := do(t, s, c.method, c.path, c.body)
		if w.Code != c.status || !strings.Contains(w.Body.String(), c.contains) {
			t.Errorf("%s %s: got %d %s, want %d containing %q", c.method, c.path, w.Code, w.Body.String(), c.status, c.contains)
		}
	}
}

func TestURLSplit(t *testing.T) {
	for in, want := range map[string][2]string{
		"https://x.example.com/a": {"https", "x.example.com"},
		"HTTP://h:80":             {"http", "h:80"},
		"http:/nohost":            {"http", ""},
		"x.example.com":           {"", ""},
		"ftp://x":                 {"ftp", "x"},
		"http://user@":            {"http", "user@"},
	} {
		s, n := urlSplit(in)
		if s != want[0] || n != want[1] {
			t.Errorf("urlSplit(%q) = %q %q, want %v", in, s, n, want)
		}
	}
	if v, err := cleanPublicBaseURL(ptr(" https://a.example.com/// ")); err != nil || v != "https://a.example.com" {
		t.Errorf("cleanPublicBaseURL = %q %v", v, err)
	}
	if _, err := cleanPublicBaseURL(ptr("a.example.com")); err == nil {
		t.Error("expected error for missing scheme")
	}
	if v, err := cleanPublicBaseURL(nil); err != nil || v != "" {
		t.Errorf("nil = %q %v", v, err)
	}
	if _, err := cleanOptionalText(ptr(strings.Repeat("é", 256)), "Service domain", 255); err == nil || err.Error() != "Service domain must be 255 characters or fewer" {
		t.Errorf("long text: %v", err)
	}
}

func ptr(s string) *string { return &s }

func TestNextLogTokens(t *testing.T) {
	got := nextLogTokens("a", []any{"b", "a", "", nil, "c", "d", "e", "f"})
	if !reflect.DeepEqual(got, bson.A{"a", "b", "c", "d", "e"}) {
		t.Errorf("got %v", got)
	}
	if got := nextLogTokens(nil, nil); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestCleanLogLines(t *testing.T) {
	lines := []string{"one\r\n", "  ", "", "two  \n\n", strings.Repeat("é", 4005)}
	for i := 0; i < 100; i++ {
		lines = append(lines, "x")
	}
	got := cleanLogLines(lines)
	if got[0] != "one" || got[1] != "two  " || len([]rune(got[2])) != 4000 || len(got) != 98 {
		t.Errorf("got %d lines: %q %q", len(got), got[0], got[1])
	}
}

func TestRenderScript(t *testing.T) {
	endpoints := map[string]string{"auth": "A", "rathole_darwin_arm64": "DA", "client_cli": "CLI"}
	fixed := map[string]string{"__PORT_HUB_MACHINE_ID__": "M", "__PORT_HUB_MACHINE_TOKEN__": "T"}
	got := renderScript("__PORT_HUB_MACHINE_ID__ __PORT_HUB_MACHINE_TOKEN__ __PORT_HUB_AUTH_URL__ __PORT_HUB_RATHOLE_DARWIN_ARM64_URL__ __PORT_HUB_CLI_URL__ __PORT_HUB_SYNC_URL__", fixed, endpoints)
	if got != "M T A DA CLI " {
		t.Errorf("got %q", got)
	}
	if installCommand(map[string]string{"install_script": "U"}, "id") != "curl -fsSL U | bash" {
		t.Error("install command")
	}
}

func TestClientBinary(t *testing.T) {
	for in, want := range map[string]string{"amd64": "x86_64", "aarch64": "arm64", "arm": "armhf", "darwin_amd64": "darwin_x86_64", "darwin_arm64": "darwin_arm64", "armv7": "armv7"} {
		if got, err := NormalizeTarget(in); err != nil || got != want {
			t.Errorf("NormalizeTarget(%q) = %q %v", in, got, err)
		}
	}
	if _, err := NormalizeTarget("mips"); err == nil || err.Error() != "Unsupported Rathole target" {
		t.Errorf("mips: %v", err)
	}
	dir := t.TempDir()
	if _, _, _, err := clientBinary(dir, "x86_64"); err == nil || err.Error() != "Asset not found: porthub-x86_64" {
		t.Errorf("missing: %v", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "porthub-arm64"), []byte("bin"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "porthub-arm64.version"), []byte("v1.2.3\n"), 0o644)
	path, asset, version, err := clientBinary(dir, "arm64")
	if err != nil || asset != "porthub-arm64" || version != "v1.2.3" || path != filepath.Join(dir, "porthub-arm64") {
		t.Errorf("got %q %q %q %v", path, asset, version, err)
	}
}

func TestPresent(t *testing.T) {
	got := present([]byte(`{"group_ids":null,"name":"x"}`))
	if !got["group_ids"] || !got["name"] || got["hostname"] {
		t.Errorf("got %v", got)
	}
}
