package core

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DirectTunnel advertises the API's existing origin HTTPS listener. Its key
// pin is delivered through the canonical authenticated API configuration.
func (a *App) DirectTunnel() (string, string) {
	base := strings.TrimRight(strings.TrimSpace(a.Cfg.TunnelDirectHTTPSBaseURL), "/")
	if base == "" {
		return "", ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", ""
	}
	appPort := os.Getenv("APP_HTTPS_PORT")
	if appPort == "" {
		appPort = "8346"
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if port != appPort && port != "443" {
		return "", ""
	}
	u.Path += "/api/tunnel"
	a.directTLSMu.Lock()
	defer a.directTLSMu.Unlock()
	if time.Now().Before(a.directTLSUntil) {
		if a.directTLSPin == "" {
			return "", ""
		}
		return u.String(), a.directTLSPin
	}
	a.directTLSUntil = time.Now().Add(time.Second)
	a.directTLSPin = ""
	// Introspection is restricted to our loopback listener and sends no
	// credentials. Remote clients verify this exact SPKI rather than disabling
	// certificate verification for the origin's self-signed certificate.
	serverName := u.Hostname()
	if canonical, e := url.Parse(a.Cfg.PublicBaseURL); e == nil && canonical.Hostname() != "" {
		serverName = canonical.Hostname()
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return "", ""
	}
	defer c.Close()
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", ""
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	a.directTLSPin = hex.EncodeToString(sum[:])
	a.directTLSUntil = time.Now().Add(30 * time.Second)
	return u.String(), a.directTLSPin
}

// WriteGatewayTrafficConfig sends the app's tunnel path straight from the
// existing public listener to the API, avoiding a second trip through 8345.
func (a *App) WriteGatewayTrafficConfig() error {
	content := managedHeader + "\n# No canonical gateway host configured.\n"
	u, err := url.Parse(a.Cfg.PublicBaseURL)
	if err == nil && u.Hostname() != "" && (u.Path == "" || u.Path == "/") && a.Cfg.TunnelWebSocket {
		listen := a.Cfg.Listen
		if listen == "" {
			listen = "127.0.0.1:47080"
		}
		rule := yamlScalar("Host(`" + strings.ToLower(u.Hostname()) + "`) && Path(`/api/tunnel`)")
		content = managedHeader + "\nhttp:\n  routers:\n    porthub_gateway_tls:\n      entryPoints: [websecure]\n      rule: " + rule + "\n      priority: 10000\n      service: porthub_gateway_api\n      tls: {}\n    porthub_gateway_http:\n      entryPoints: [web]\n      rule: " + rule + "\n      priority: 10000\n      service: porthub_gateway_api\n  services:\n    porthub_gateway_api:\n      loadBalancer:\n        servers:\n          - url: " + yamlScalar("http://"+listen) + "\n"
	}
	return writeAtomic(filepath.Join(filepath.Dir(a.Cfg.TraefikConfigPath), "porthub-gateway.yml"), ".gateway-", content, true)
}

func (a *App) DirectTunnelHost() string {
	u, err := url.Parse(a.Cfg.PublicBaseURL)
	if err != nil {
		return ""
	}
	return u.Host
}
