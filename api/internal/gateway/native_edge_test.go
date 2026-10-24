package gateway

// Transitional verification against the deployed agent protocol. This test is
// opt-in while the native replacement is being developed; it never contacts a
// production host or installs a client.
import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"testing"
	"time"
)

func TestNativeEdgeWithExistingGoAgent(t *testing.T) {
	edgeBinary := os.Getenv("PORTHUB_TEST_EDGE_BINARY")
	if edgeBinary == "" {
		t.Skip("set PORTHUB_TEST_EDGE_BINARY to the native edge executable")
	}
	agentBinary := os.Getenv("PORTHUB_TEST_CLIENT_BINARY")
	if agentBinary == "" {
		t.Fatal("set PORTHUB_TEST_CLIENT_BINARY to the existing Go agent executable")
	}
	for _, websocketOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("websocket_only_%v", websocketOnly), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			target := mustListen(t)
			result := make(chan error, 1)
			go func() {
				c, err := target.Accept()
				if err != nil {
					result <- err
					return
				}
				defer c.Close()
				data, err := io.ReadAll(c)
				if err == nil {
					_, err = c.Write(append([]byte("reply:"), data...))
				}
				result <- err
			}()
			public := freeAddress(t)
			ingress := freeAddress(t)
			directory := t.TempDir()
			config := filepath.Join(directory, "edge.toml")
			if err := os.WriteFile(config, []byte(fmt.Sprintf("[server.services.test]\ntoken='secret'\nbind_addr=%q\n", public)), 0600); err != nil {
				t.Fatal(err)
			}
			edge := exec.CommandContext(ctx, edgeBinary, "--listen", ingress, "--config", config)
			edgeLog, err := os.Create(filepath.Join(directory, "edge.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer edgeLog.Close()
			edge.Stdout, edge.Stderr = edgeLog, edgeLog
			if err := edge.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = edge.Wait() }()
			remote := "http://" + ingress + "/api/tunnel"
			if websocketOnly {
				upstream, _ := url.Parse("http://" + ingress)
				proxy := httputil.NewSingleHostReverseProxy(upstream)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.EqualFold(r.Header.Get("Upgrade"), "porthub.tcp.v1") {
						http.Error(w, "upgrade disabled", 400)
						return
					}
					proxy.ServeHTTP(w, r)
				}))
				defer server.Close()
				remote = server.URL + "/api/tunnel"
			}
			config = filepath.Join(directory, "client.toml")
			if err := os.WriteFile(config, []byte(fmt.Sprintf("[client]\nremote_addr=%q\n[client.services.test]\ntoken='secret'\nlocal_addr=%q\n", remote, target.Addr().String())), 0600); err != nil {
				t.Fatal(err)
			}
			agent := exec.CommandContext(ctx, agentBinary, "-c", config)
			agentLog, err := os.Create(filepath.Join(directory, "agent.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer agentLog.Close()
			agent.Stdout, agent.Stderr = agentLog, agentLog
			if err := agent.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = agent.Wait() }()
			var visitor net.Conn
			for ctx.Err() == nil {
				visitor, err = net.DialTimeout("tcp", public, 100*time.Millisecond)
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				logs, _ := os.ReadFile(edgeLog.Name())
				t.Fatalf("connect public listener: %v; %s", err, logs)
			}
			defer visitor.Close()
			_ = visitor.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{0, 1, 2, 255, 42, 13, 10}, 300000)
			if _, err := visitor.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := visitor.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(visitor)
			if err != nil {
				logs, _ := os.ReadFile(agentLog.Name())
				t.Fatalf("read response: %v; %s", err, logs)
			}
			if !bytes.Equal(response, append([]byte("reply:"), payload...)) {
				t.Fatalf("corrupted half-close response: got %d bytes", len(response))
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeClientWithExistingGoGateway(t *testing.T) {
	binary := os.Getenv("PORTHUB_TEST_NATIVE_CLIENT_BINARY")
	if binary == "" {
		t.Skip("set PORTHUB_TEST_NATIVE_CLIENT_BINARY to the native agent executable")
	}
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprintf("http_upgrade_%v", direct), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			gateway := New(ctx)
			defer gateway.Close()
			public := freeAddress(t)
			if err := gateway.Apply(Config{map[string]Service{"test": {Token: "secret", Bind: public}}}); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(gateway.Handler))
			defer server.Close()
			target := mustListen(t)
			result := make(chan error, 1)
			go func() {
				c, err := target.Accept()
				if err != nil {
					result <- err
					return
				}
				defer c.Close()
				data, err := io.ReadAll(c)
				if err == nil {
					_, err = c.Write(append([]byte("reply:"), data...))
				}
				result <- err
			}()
			directory := t.TempDir()
			config := filepath.Join(directory, "client.toml")
			address := strings.TrimPrefix(server.URL, "http://")
			data := fmt.Sprintf("[client]\nremote_addr=%q\nretry_interval=1\n[client.transport]\ntype='websocket'\n[client.transport.websocket]\ntls=false\npath='/'\nporthub_framing=true\nhttp_upgrade=%v\n[client.services.test]\ntoken='secret'\nlocal_addr=%q\n", address, direct, target.Addr().String())
			if err := os.WriteFile(config, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			logFile, err := os.Create(filepath.Join(directory, "native-agent.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			agent := exec.CommandContext(ctx, binary, "-c", config)
			agent.Stdout, agent.Stderr = logFile, logFile
			if err := agent.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = agent.Wait() }()
			for {
				gateway.mu.Lock()
				service := gateway.services[sha256.Sum256([]byte("test"))]
				ready := service != nil && service.session != nil
				gateway.mu.Unlock()
				if ready {
					break
				}
				if ctx.Err() != nil {
					logs, _ := os.ReadFile(logFile.Name())
					t.Fatalf("native client did not authenticate: %s", logs)
				}
				time.Sleep(10 * time.Millisecond)
			}
			c, err := net.Dial("tcp", public)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{1, 2, 255, 0, 7, 13, 10}, 300000)
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(c)
			if err != nil {
				logs, _ := os.ReadFile(logFile.Name())
				t.Fatalf("response: %v; %s", err, logs)
			}
			if !bytes.Equal(response, append([]byte("reply:"), payload...)) {
				t.Fatalf("corrupted half-close response: %d bytes", len(response))
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
