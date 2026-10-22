package access

import (
	"github.com/algofly-oss/porthub/api/internal/auth"
	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/policy"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessRoutes(t *testing.T) {
	s, err := httpapi.New()
	if err != nil {
		t.Fatal(err)
	}
	Register(s.API, &core.App{Sessions: &auth.Sessions{Cookie: "porthub_session"}})
	for _, tc := range []struct {
		method, path, body string
		status             int
		contains           string
	}{
		{"GET", "/api/access/workspaces", "", 400, "User not logged in"},
		{"GET", "/api/access/snapshot", "", 400, "User not logged in"},
		{"POST", "/api/access/books", `{}`, 422, `group_id`},
		{"DELETE", "/api/access/books/a", `{"revision":0}`, 422, "greater than or equal"},
		{"PUT", "/api/access/groups/a/members", `{"machine_ids":null}`, 422, "none is not an allowed value"},
		{"PUT", "/api/access/network", `{}`, 400, "User not logged in"},
		{"POST", "/api/access/test", `{"source_id":"a","destination_id":"b"}`, 400, "User not logged in"},
		{"POST", "/api/access/invitations", `{"email":"bad"}`, 422, "Enter a valid email"},
		{"POST", "/api/access/invitations/preview", `{"token":"short"}`, 422, "at least 32"},
		{"POST", "/api/access/private/peers", `{"machine_id":"bad"}`, 400, "User not logged in"},
		{"PUT", "/api/access/private/peers/a/hostname", `{"hostname":"bad name"}`, 422, "Use up to 48"},
		{"PUT", "/api/access/private/peers/a", `{"enabled":"yes"}`, 400, "User not logged in"},
		{"POST", "/api/access/private/bootstrap", `{}`, 422, "ticket"},
		{"POST", "/api/access/private/sync", `{}`, 422, "fingerprint"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.Mux.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("got %d %s; want %d containing %q", w.Code, w.Body.String(), tc.status, tc.contains)
			}
		})
	}
}
func TestWorkspaceOrigin(t *testing.T) {
	for _, tc := range []struct {
		origin string
		ok     bool
	}{{"https://hub.example", true}, {"https://hub.example:443", false}, {"https://other.example", false}, {"https://hub.example@other.example", false}, {"null", false}, {"", true}} {
		r := httptest.NewRequest("POST", "http://hub.example/", nil)
		r.Header.Set("Origin", tc.origin)
		if ok := checkOrigin(r) == nil; ok != tc.ok {
			t.Errorf("%+v got %v", tc, ok)
		}
	}
}
func TestSignalIdentity(t *testing.T) {
	f := strings.Repeat("AA:", 31) + "AA"
	s := policy.Signal{Description: policy.Description{Type: "offer", SDP: "v=0\r\na=fingerprint:sha-256 " + strings.ToLower(f) + "\r\n"}}
	if err := validateSignal("a", "b", s, f); err != nil {
		t.Fatal(err)
	}
	if err := validateSignal("b", "a", s, f); err == nil {
		t.Fatal("accepted reversed negotiation")
	}
	s.Description.SDP += "a=fingerprint:sha-256 " + strings.Repeat("BB:", 31) + "BB\r\n"
	if err := validateSignal("a", "b", s, f); err == nil {
		t.Fatal("accepted mismatched certificate")
	}
}
func TestICEConfiguration(t *testing.T) {
	t.Setenv("PORTHUB_RELAY_SECRET", "")
	t.Setenv("PORTHUB_PRIVATE_ICE_SERVERS", `[{"urls":["stun:example.org"]},{"urls":["https:bad"]},{"urls":"stun:bad"},null]`)
	if got := iceServers("peer"); len(got) != 1 {
		t.Fatalf("invalid ICE servers leaked: %#v", got)
	}
	t.Setenv("PORTHUB_RELAY_SECRET", strings.Repeat("x", 32))
	if got := iceServers("peer"); len(got) != 2 {
		t.Fatalf("missing relay credential: %#v", got)
	}
}
