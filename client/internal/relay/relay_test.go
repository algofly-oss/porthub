package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

const secret = "relay-test-secret-0123456789abcdefghij"

func TestSpeedTestNeedsValidCredential(t *testing.T) {
	server, err := NewServer(secret, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	web := httptest.NewServer(server)
	defer web.Close()
	user, pass, _ := turn.GenerateLongTermTURNRESTCredentials(secret, "w:p", time.Hour)
	if score, err := Measure(context.Background(), web.URL, user, pass); err != nil || score <= 0 {
		t.Fatalf("valid credential: %v %v", score, err)
	}
	expiredUser, expiredPass, _ := turn.GenerateLongTermTURNRESTCredentials(secret, "w:p", -time.Minute)
	for _, c := range [][2]string{{user, "forged"}, {expiredUser, expiredPass}, {"", ""}} {
		req, _ := http.NewRequest(http.MethodGet, web.URL+SpeedPath+"?bytes=10", nil)
		req.Header.Set("X-Relay-User", c[0])
		req.Header.Set("X-Relay-Credential", c[1])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("credential %q accepted: %d", c[0], resp.StatusCode)
		}
	}
}
