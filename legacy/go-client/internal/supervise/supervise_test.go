//go:build !windows

package supervise

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	procs, err := Parse(strings.NewReader("# comment\n\napi: after=127.0.0.1:27017 uvicorn main:app --port 8080\nui: node server.js\n"))
	if err != nil || len(procs) != 2 || procs[0].After != "127.0.0.1:27017" || procs[0].Command != "uvicorn main:app --port 8080" || procs[1].After != "" {
		t.Fatalf("%+v %v", procs, err)
	}
	if _, err := Parse(strings.NewReader("broken line\n")); err == nil {
		t.Fatal("accepted invalid line")
	}
}

func TestRestartsOrderAndStop(t *testing.T) {
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	procs := []Process{
		{Name: "flaky", Command: "sh -c 'echo x >> " + count + "; exit 1'"},
		{Name: "dependent", After: addr, Command: "sh -c 'touch " + filepath.Join(dir, "started") + "; sleep 60'"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, procs, 2*time.Second) }()
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
		t.Fatal("dependent started before its port answered")
	}
	l2, _ := net.Listen("tcp", addr)
	defer l2.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dependent never started")
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, _ := os.ReadFile(count)
	if strings.Count(string(b), "x") < 2 {
		t.Fatal("exited process was not restarted")
	}
	start := time.Now()
	cancel()
	<-done
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not stop promptly")
	}
}
