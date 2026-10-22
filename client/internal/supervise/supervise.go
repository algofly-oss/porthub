//go:build !windows

// Package supervise runs the processes of the single PortHub server
// container: start in order (optionally after a TCP port answers), restart
// whatever exits with backoff, forward shutdown signals, prefix logs.
//
// Procfile lines:  name: [after=HOST:PORT] command...
// Blank lines and lines starting with # are ignored.
package supervise

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Process struct {
	Name, After, Command string
}

func Parse(r io.Reader) ([]Process, error) {
	var out []Process
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, ok := strings.Cut(line, ":")
		name, rest = strings.TrimSpace(name), strings.TrimSpace(rest)
		if !ok || name == "" || rest == "" {
			return nil, fmt.Errorf("procfile line %d: want 'name: command'", n)
		}
		p := Process{Name: name}
		if after, command, ok := strings.Cut(rest, " "); ok && strings.HasPrefix(after, "after=") {
			p.After, rest = strings.TrimPrefix(after, "after="), strings.TrimSpace(command)
		}
		p.Command = rest
		out = append(out, p)
	}
	return out, scanner.Err()
}

func waitPort(ctx context.Context, address string) error {
	for {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type prefixWriter struct {
	name string
	mu   *sync.Mutex
	buf  []byte
}

func (w *prefixWriter) Write(b []byte) (int, error) {
	w.buf = append(w.buf, b...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		w.mu.Lock()
		fmt.Fprintf(os.Stdout, "[%s] %s\n", w.name, w.buf[:i])
		w.mu.Unlock()
		w.buf = w.buf[i+1:]
	}
	return len(b), nil
}

// Run supervises the processes until ctx is cancelled, then stops them all
// (SIGTERM to each process group, SIGKILL after grace).
func Run(ctx context.Context, procs []Process, grace time.Duration) error {
	if len(procs) == 0 {
		return errors.New("no processes to supervise")
	}
	var out sync.Mutex
	var wg sync.WaitGroup
	for _, p := range procs {
		if p.After != "" {
			log.Printf("supervise: %s waits for %s", p.Name, p.After)
			if err := waitPort(ctx, p.After); err != nil {
				break
			}
		}
		wg.Add(1)
		go func(p Process) {
			defer wg.Done()
			backoff := time.Second
			for ctx.Err() == nil {
				cmd := exec.Command("/bin/sh", "-c", p.Command)
				w := &prefixWriter{name: p.Name, mu: &out}
				cmd.Stdout, cmd.Stderr = w, w
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				started := time.Now()
				if err := cmd.Start(); err != nil {
					log.Printf("supervise: %s failed to start: %v", p.Name, err)
				} else {
					done := make(chan error, 1)
					go func() { done <- cmd.Wait() }()
					select {
					case err := <-done:
						log.Printf("supervise: %s exited: %v", p.Name, err)
					case <-ctx.Done():
						_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
						select {
						case <-done:
						case <-time.After(grace):
							_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
							<-done
						}
						log.Printf("supervise: %s stopped", p.Name)
						return
					}
				}
				if time.Since(started) > time.Minute {
					backoff = time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, 30*time.Second)
			}
		}(p)
	}
	wg.Wait()
	return nil
}
