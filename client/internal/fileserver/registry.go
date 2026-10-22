package fileserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Each running server owns a control socket in a private per-user directory.
// Stopping talks to that socket rather than signalling a PID, so a stale record
// can never stop an unrelated process that later reused the PID.
type Record struct {
	PID     int       `json:"pid"`
	Port    int       `json:"port"`
	Bind    string    `json:"bind"`
	Root    string    `json:"root"`
	Started time.Time `json:"started"`
}

func runtimeDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, fmt.Sprintf("porthub-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	// Refuse a directory planted by someone else in a shared temp location.
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !private(info) {
		return "", fmt.Errorf("unsafe runtime directory %s", dir)
	}
	return dir, nil
}
func socketPath(dir string, port int) string {
	return filepath.Join(dir, fmt.Sprintf("http-%d.sock", port))
}

type control struct {
	listener net.Listener
	path     string
}

// register claims the control socket for port. stop is called on request.
func register(r Record, stop func()) (*control, error) {
	dir, err := runtimeDir()
	if err != nil {
		return nil, err
	}
	path := socketPath(dir, r.Port)
	if _, err := query(path, "info"); err == nil {
		return nil, fmt.Errorf("a porthub http.server is already running on port %d", r.Port)
	}
	_ = os.Remove(path) // stale socket from a killed process
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	info, _ := json.Marshal(r)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				line, _ := bufio.NewReader(conn).ReadString('\n')
				switch strings.TrimSpace(line) {
				case "info":
					conn.Write(append(info, '\n'))
				case "stop":
					conn.Write([]byte("stopping\n"))
					stop()
				}
			}(conn)
		}
	}()
	return &control{listener: listener, path: path}, nil
}
func (c *control) Close() {
	c.listener.Close()
	_ = os.Remove(c.path)
}
func query(path, command string) (string, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte(command + "\n")); err != nil {
		return "", err
	}
	return bufio.NewReader(conn).ReadString('\n')
}

// List returns running servers and removes sockets left by killed processes.
func List() ([]Record, error) {
	dir, err := runtimeDir()
	if err != nil {
		return nil, err
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "http-*.sock"))
	var records []Record
	for _, path := range matches {
		reply, err := query(path, "info")
		if err != nil {
			_ = os.Remove(path)
			continue
		}
		var r Record
		if json.Unmarshal([]byte(reply), &r) == nil {
			records = append(records, r)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Port < records[j].Port })
	return records, nil
}

// Stop asks the server on port (0 = all of this user's servers) to shut down
// gracefully and waits until its socket is gone.
func Stop(port int) ([]Record, error) {
	records, err := List()
	if err != nil {
		return nil, err
	}
	dir, _ := runtimeDir()
	var stopped []Record
	for _, r := range records {
		if port != 0 && r.Port != port {
			continue
		}
		path := socketPath(dir, r.Port)
		if _, err := query(path, "stop"); err != nil {
			return stopped, err
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := query(path, "info"); err != nil {
				break
			}
			if time.Now().After(deadline) {
				return stopped, fmt.Errorf("server on port %d did not stop", r.Port)
			}
			time.Sleep(100 * time.Millisecond)
		}
		stopped = append(stopped, r)
	}
	if port != 0 && len(stopped) == 0 {
		return nil, errors.New("no porthub http.server is running on port " + strconv.Itoa(port) + " for this user")
	}
	return stopped, nil
}
