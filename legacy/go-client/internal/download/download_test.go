package download

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func payload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
func serve(content *[]byte, etag *string, ranges bool, requests *int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(requests, 1)
		if !ranges {
			w.Write(*content)
			return
		}
		w.Header().Set("ETag", *etag)
		http.ServeContent(w, r, "file.bin", time.Unix(1700000000, 0), bytes.NewReader(*content))
	}))
}

func TestParallelRangedDownload(t *testing.T) {
	content, etag, requests := payload(t, 5*MinSegment+123), `"v1"`, int64(0)
	server := serve(&content, &etag, true, &requests)
	defer server.Close()
	dir := t.TempDir()
	got, err := Get(context.Background(), Options{URL: server.URL + "/dir/file.bin", Dir: dir, Connections: 4})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "file.bin" {
		t.Fatalf("unexpected name %s", got)
	}
	b, _ := os.ReadFile(got)
	if !bytes.Equal(b, content) {
		t.Fatal("content mismatch")
	}
	if requests < 5 {
		t.Fatalf("expected parallel segment requests, got %d", requests)
	}
	if _, err := os.Stat(got + ".porthub-part.json"); !os.IsNotExist(err) {
		t.Fatal("control file left behind")
	}
	// An existing complete file is never overwritten.
	again, err := Get(context.Background(), Options{URL: server.URL + "/dir/file.bin", Dir: dir})
	if err != nil || filepath.Base(again) != "file.1.bin" {
		t.Fatalf("existing file not preserved: %s %v", again, err)
	}
}

func TestResumeOnlyWhenUnchanged(t *testing.T) {
	content, etag, requests := payload(t, 3*MinSegment), `"v1"`, int64(0)
	server := serve(&content, &etag, true, &requests)
	defer server.Close()
	dir := t.TempDir()
	target := filepath.Join(dir, "file.bin")
	// Simulate an interrupted run: first segment half written.
	s := plan(server.URL+"/file.bin", remote{size: int64(len(content)), etag: etag}, 3)
	s.Segments[0].Done = MinSegment / 2
	part := make([]byte, len(content))
	copy(part, content[:MinSegment/2])
	os.WriteFile(target+".porthub-part", part, 0644)
	save(target+".porthub-part.json", s)
	got, err := Get(context.Background(), Options{URL: server.URL + "/file.bin", Dir: dir, Connections: 3})
	if err != nil || got != target {
		t.Fatal(got, err)
	}
	b, _ := os.ReadFile(got)
	if !bytes.Equal(b, content) {
		t.Fatal("resumed content mismatch")
	}

	// A changed remote file discards stale partial data instead of mixing it.
	os.Remove(target)
	stale := make([]byte, len(content))
	os.WriteFile(target+".porthub-part", stale, 0644)
	s.Segments[0].Done = MinSegment
	save(target+".porthub-part.json", s)
	content, etag = payload(t, len(content)), `"v2"`
	got, err = Get(context.Background(), Options{URL: server.URL + "/file.bin", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(got)
	if !bytes.Equal(b, content) {
		t.Fatal("stale partial data reused after the remote file changed")
	}
}

func TestServerWithoutRanges(t *testing.T) {
	content, etag, requests := payload(t, 100000), "", int64(0)
	server := serve(&content, &etag, false, &requests)
	defer server.Close()
	got, err := Get(context.Background(), Options{URL: server.URL + "/", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "index.html" {
		t.Fatalf("unexpected name %s", got)
	}
	b, _ := os.ReadFile(got)
	if !bytes.Equal(b, content) {
		t.Fatal("content mismatch")
	}
}

func TestFileNamesCannotEscape(t *testing.T) {
	for raw, disposition := range map[string]string{"http://h/a/../../etc/passwd": "", "http://h/x": "../../.bashrc", "http://h/": "..\\evil"} {
		name := fileName(raw, disposition)
		if strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
			t.Fatalf("unsafe name %q", name)
		}
	}
	if _, err := Get(context.Background(), Options{URL: "file:///etc/passwd", Dir: t.TempDir()}); err == nil {
		t.Fatal("non-http URL accepted")
	}
}
