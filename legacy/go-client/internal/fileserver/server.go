// Package fileserver replaces the lighttpd helper used by `porthub http.server`.
// It runs only in the foreground for the invoking user: nothing is installed,
// no system service is created and no port is bound unless asked for.
package fileserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Options struct {
	Port int
	Path string
	Bind string
}

// Handler serves directory listings and files. http.ServeContent provides
// byte Range, If-Range, If-Modified-Since and HEAD semantics for media players
// and resumable downloads.
func Handler(root string, logger *log.Logger) http.Handler {
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		files.ServeHTTP(recorder, r)
		if logger != nil {
			logger.Printf("%s %s %q %d %d %s", r.RemoteAddr, r.Method, r.URL.RequestURI(), recorder.status, recorder.bytes, time.Since(started).Round(time.Millisecond))
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// ReadFrom delegates to the underlying writer so io.Copy keeps the kernel
// sendfile fast path for large files.
func (s *statusRecorder) ReadFrom(r io.Reader) (int64, error) {
	from, ok := s.ResponseWriter.(io.ReaderFrom)
	if !ok {
		return io.Copy(struct{ io.Writer }{s}, r)
	}
	n, err := from.ReadFrom(r)
	s.bytes += n
	return n, err
}

func Serve(ctx context.Context, o Options) error {
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("HTTP server port must be between 1 and 65535")
	}
	root, err := filepath.Abs(o.Path)
	if err != nil {
		return err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return fmt.Errorf("document root does not exist: %s", root)
	}
	if net.ParseIP(o.Bind) == nil && o.Bind != "localhost" {
		return fmt.Errorf("invalid bind address: %s", o.Bind)
	}
	address := net.JoinHostPort(o.Bind, strconv.Itoa(o.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "[porthub-http.server] ", log.LstdFlags)
	server := &http.Server{Handler: Handler(root, logger), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute}
	stopRequested := make(chan struct{}, 1)
	control, err := register(Record{PID: os.Getpid(), Port: o.Port, Bind: o.Bind, Root: root, Started: time.Now()}, func() {
		select {
		case stopRequested <- struct{}{}:
		default:
		}
	})
	if err != nil {
		listener.Close()
		return err
	}
	defer control.Close()
	logger.Printf("Serving %s on %s (stop from any terminal: porthub http.server stop %d)", root, address, o.Port)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	case <-stopRequested:
		logger.Print("Stop requested from another terminal")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		// Long downloads still in progress: close them rather than hold the port.
		return server.Close()
	}
	logger.Printf("Stopped; port %d released", o.Port)
	return nil
}
