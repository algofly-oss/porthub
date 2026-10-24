package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustListen(t testing.TB) net.Listener {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return l
}
func freeAddress(t testing.TB) string {
	l := mustListen(t)
	a := l.Addr().String()
	l.Close()
	return a
}

func setup(t testing.TB, ws bool, halfClose bool) (string, *Gateway, Config) {
	return setupWithServer(t, ws, halfClose, "")
}

func setupWithServer(t testing.TB, ws bool, halfClose bool, rustBinary string) (string, *Gateway, Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g := New(ctx)
	t.Cleanup(g.Close)
	backend := mustListen(t)
	go func() {
		for {
			c, e := backend.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				if halfClose {
					data, _ := io.ReadAll(c)
					_, _ = c.Write(append([]byte("reply:"), data...))
				} else {
					_, _ = io.Copy(c, c)
				}
			}()
		}
	}()
	addr := freeAddress(t)
	cfg := Config{map[string]Service{"test": {Token: "test-secret", Bind: addr}}}
	if e := func() error {
		if rustBinary != "" {
			return nil
		}
		return g.Apply(cfg)
	}(); e != nil {
		t.Fatal(e)
	}
	remote := ""
	certFile := ""
	directConfig := ""
	if ws {
		api := httptest.NewServer(http.HandlerFunc(g.Handler))
		t.Cleanup(api.Close)
		backendURL, _ := url.Parse(api.URL)
		proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(backendURL))
		t.Cleanup(proxy.Close)
		proxyURL, _ := url.Parse(proxy.URL)
		h := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(proxyURL))
		t.Cleanup(h.Close)
		remote = "ws" + strings.TrimPrefix(h.URL, "http")
		certFile = filepath.Join(t.TempDir(), "gateway.crt")
		pin := sha256.Sum256(h.Certificate().RawSubjectPublicKeyInfo)
		directConfig = fmt.Sprintf("direct_addr=%q\ndirect_spki_sha256=%q\ndirect_host=%q\n", h.URL, hex.EncodeToString(pin[:]), "porthub.test")
		if e := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if !ws {
		if rustBinary == "" {
			l := mustListen(t)
			go g.ServeLegacy(l)
			remote = l.Addr().String()
		} else {
			remote = freeAddress(t)
			path := filepath.Join(t.TempDir(), "server.toml")
			data := fmt.Sprintf("[server]\nbind_addr=%q\n[server.services.test]\ntoken=%q\nbind_addr=%q\nnodelay=true\n", remote, "test-secret", addr)
			if e := os.WriteFile(path, []byte(data), 0600); e != nil {
				t.Fatal(e)
			}
			server := exec.CommandContext(ctx, rustBinary, "-s", path)
			if e := server.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { cancel(); _ = server.Wait() })
		}
	}
	binaryPath := os.Getenv("PORTHUB_TEST_CLIENT_BINARY")
	if binaryPath == "" {
		binaryPath = filepath.Join(t.TempDir(), "porthub")
		cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/porthub")
		cmd.Dir = "../../../client"
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build Go agent: %v\n%s", e, out)
		}
	}
	configPath := filepath.Join(t.TempDir(), "client.toml")
	data := fmt.Sprintf("[client]\nremote_addr=%q\n[client.services.test]\ntoken=%q\nlocal_addr=%q\n", remote, "test-secret", backend.Addr().String())
	if directConfig != "" && os.Getenv("PORTHUB_TEST_WEBSOCKET_ONLY") != "1" {
		data = strings.Replace(data, "[client]\n", "[client]\n"+directConfig, 1)
	}
	if e := os.WriteFile(configPath, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, binaryPath, "-c", configPath)
	if certFile != "" {
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile)
	}
	// Keep logs in a file so concurrent tests never race on an output buffer.
	logFile, e := os.Create(filepath.Join(t.TempDir(), "agent.log"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { logFile.Close() })
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	until := time.Now().Add(10 * time.Second)
	for {
		g.mu.Lock()
		active := false
		if s := g.services[sha256.Sum256([]byte("test"))]; s != nil {
			active = s.session != nil
		}
		g.mu.Unlock()
		if rustBinary != "" {
			if c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond); e == nil {
				c.Close()
				active = true
			}
		}
		if active {
			break
		}
		if time.Now().After(until) {
			out, _ := os.ReadFile(logFile.Name())
			t.Fatalf("agent did not connect: %s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr, g, cfg
}

func TestWebSocketFallbackCompatibility(t *testing.T) {
	t.Setenv("PORTHUB_TEST_WEBSOCKET_ONLY", "1")
	addr, _, _ := setup(t, true, true)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("websocket"))
	_ = c.(*net.TCPConn).CloseWrite()
	data, err := io.ReadAll(c)
	if err != nil || string(data) != "reply:websocket" {
		t.Fatalf("WebSocket fallback: %q %v", data, err)
	}
}

func TestPortHubAgentRoundTrip(t *testing.T) {
	for _, ws := range []bool{false, true} {
		t.Run(fmt.Sprint("websocket=", ws), func(t *testing.T) {
			addr, _, _ := setup(t, ws, true)
			c, e := net.Dial("tcp", addr)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("large request"), 100000)
			if _, e = c.Write(payload); e != nil {
				t.Fatal(e)
			}
			_ = c.(*net.TCPConn).CloseWrite()
			got, e := io.ReadAll(c)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, append([]byte("reply:"), payload...)) {
				t.Fatalf("half-close response mismatch: %d bytes", len(got))
			}
		})
	}
}

func TestRevokeActiveAndQueuedChannels(t *testing.T) {
	addr, g, _ := setup(t, true, false)
	c, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("hello"))
	b := make([]byte, 5)
	if _, e = io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	if e = g.Apply(Config{map[string]Service{}}); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Read(b); e == nil {
		t.Fatal("revoked active stream survived")
	}
	if c, e := net.DialTimeout("tcp", addr, time.Second); e == nil {
		c.Close()
		t.Fatal("removed listener survived")
	}
}

func TestRejectUnauthenticatedAndMalformed(t *testing.T) {
	g := New(context.Background())
	defer g.Close()
	addr := freeAddress(t)
	cfg := Config{map[string]Service{"test": {Token: "secret", Bind: addr}}}
	if e := g.Apply(cfg); e != nil {
		t.Fatal(e)
	}
	for _, unknown := range []bool{false, true} {
		server, client := net.Pipe()
		go g.Handle(server)
		_ = client.SetDeadline(time.Now().Add(time.Second))
		key := sha256.Sum256([]byte("test"))
		if unknown {
			key = sha256.Sum256([]byte("other"))
		}
		hello := make([]byte, 37)
		hello[4] = 1
		copy(hello[5:], key[:])
		_, _ = client.Write(hello)
		reply := make([]byte, 37)
		if _, e := io.ReadFull(client, reply); e != nil {
			t.Fatal(e)
		}
		if !unknown {
			_, _ = client.Write(make([]byte, 32))
		}
		var ack [4]byte
		if _, e := io.ReadFull(client, ack[:]); e != nil {
			t.Fatal(e)
		}
		want := uint32(2)
		if unknown {
			want = 1
		}
		if binary.LittleEndian.Uint32(ack[:]) != want {
			t.Fatal("incorrect auth rejection")
		}
		client.Close()
	}
	r := httptest.NewRecorder()
	g.Handler(r, httptest.NewRequest("GET", "/api/tunnel", nil))
	if r.Code != 400 {
		t.Fatal(r.Code)
	}
}

func TestEmptyConfigurationRevokesEveryService(t *testing.T) {
	addr, g, _ := setup(t, false, false)
	cfg, err := Parse([]byte("[server]\n[server.services]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("empty configuration kept a public listener")
	}
}

func TestConcurrentAndReload(t *testing.T) {
	addr, g, cfg := setup(t, true, false)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := net.Dial("tcp", addr)
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			p := bytes.Repeat([]byte("x"), 128*1024)
			go func() { _, _ = c.Write(p) }()
			b := make([]byte, len(p))
			if _, e = io.ReadFull(c, b); e != nil {
				t.Error(e)
			}
			if !bytes.Equal(p, b) {
				t.Error("payload corruption")
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if e := g.Apply(cfg); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
}

func BenchmarkGateway(b *testing.B) {
	for _, ws := range []bool{false, true} {
		b.Run(fmt.Sprint("websocket=", ws), func(b *testing.B) {
			addr, _, _ := setup(b, ws, false)
			c, e := net.Dial("tcp", addr)
			if e != nil {
				b.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
			payload := make([]byte, 64*1024)
			response := make([]byte, len(payload))
			b.SetBytes(int64(len(payload) * 2))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, e = c.Write(payload); e != nil {
					b.Fatal(e)
				}
				if _, e = io.ReadFull(c, response); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

func BenchmarkRathole(b *testing.B) {
	binaryPath := os.Getenv("PORTHUB_TEST_RATHOLE_BINARY")
	if binaryPath == "" {
		b.Skip("set PORTHUB_TEST_RATHOLE_BINARY to a v0.5.0 reference binary")
	}
	addr, _, _ := setupWithServer(b, false, false, binaryPath)
	c, e := net.Dial("tcp", addr)
	if e != nil {
		b.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	payload := make([]byte, 64*1024)
	response := make([]byte, len(payload))
	b.SetBytes(int64(len(payload) * 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e = c.Write(payload); e != nil {
			b.Fatal(e)
		}
		if _, e = io.ReadFull(c, response); e != nil {
			b.Fatal(e)
		}
	}
}

func benchmarkStream(b *testing.B, ws bool, rust string) {
	addr, _, _ := setupWithServer(b, ws, false, rust)
	c, e := net.Dial("tcp", addr)
	if e != nil {
		b.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	payload := make([]byte, 64*1024)
	b.SetBytes(int64(len(payload) * 2))
	b.ResetTimer()
	written := make(chan error, 1)
	go func() {
		for i := 0; i < b.N; i++ {
			if _, err := c.Write(payload); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	if _, e := io.CopyN(io.Discard, c, int64(b.N)*int64(len(payload))); e != nil {
		c.Close()
		b.Fatal(e)
	}
	if e := <-written; e != nil {
		b.Fatal(e)
	}
}

func BenchmarkStreamGateway(b *testing.B) {
	for _, ws := range []bool{false, true} {
		b.Run(fmt.Sprint("websocket=", ws), func(b *testing.B) { benchmarkStream(b, ws, "") })
	}
}

func BenchmarkStreamRathole(b *testing.B) {
	binaryPath := os.Getenv("PORTHUB_TEST_RATHOLE_BINARY")
	if binaryPath == "" {
		b.Skip("set PORTHUB_TEST_RATHOLE_BINARY")
	}
	benchmarkStream(b, false, binaryPath)
}
