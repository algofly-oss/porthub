package core

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algofly-oss/porthub/api/internal/config"
)

func TestOriginCertificatePinAndTransportVersion(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	t.Setenv("APP_HTTPS_PORT", port)
	a := &App{Cfg: config.Config{TunnelDirectHTTPSBaseURL: server.URL, TunnelWebSocket: true}}
	endpoint, pin := a.DirectTunnel()
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	if endpoint != server.URL+"/api/tunnel" || pin != hex.EncodeToString(sum[:]) {
		t.Fatal("incorrect origin certificate pin")
	}
	first := a.machineTransportVersion(Doc{}, nil, "first")
	second := a.machineTransportVersion(Doc{}, nil, "second")
	if first == second {
		t.Fatal("transport change did not invalidate configuration")
	}
	if first != a.machineTransportVersion(Doc{}, nil, "first") {
		t.Fatal("unchanged transport changed configuration version")
	}
}

func TestGatewayPublicRouteOnlyMatchesItsOwnEndpoint(t *testing.T) {
	a := &App{Cfg: config.Config{PublicBaseURL: "https://porthub.example", Listen: "127.0.0.1:47080", TunnelWebSocket: true, TraefikConfigPath: filepath.Join(t.TempDir(), "traffic-routes.yml")}}
	if err := a.WriteGatewayTrafficConfig(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(a.Cfg.TraefikConfigPath), "porthub-gateway.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Host(`porthub.example`) && Path(`/api/tunnel`)", "http://127.0.0.1:47080", "entryPoints: [websecure]"} {
		if !strings.Contains(string(b), s) {
			t.Fatal("missing gateway route: " + s)
		}
	}
	if strings.Contains(string(b), "8345") || strings.Contains(string(b), "PathPrefix") {
		t.Fatal("gateway route changes unrelated paths or adds a proxy hop")
	}
}
