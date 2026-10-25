package fileserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRangeListingAndContainment(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "video.mp4"), []byte("0123456789"), 0644)
	os.Mkdir(filepath.Join(root, "sub"), 0755)
	secret := filepath.Join(filepath.Dir(root), "outside.txt")
	os.WriteFile(secret, []byte("secret"), 0644)
	defer os.Remove(secret)
	server := httptest.NewServer(Handler(root, nil))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/video.mp4", nil)
	req.Header.Set("Range", "bytes=2-5")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || string(body) != "2345" || resp.Header.Get("Content-Range") != "bytes 2-5/10" || resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("range not served: %d %q %v", resp.StatusCode, body, resp.Header)
	}

	resp, _ = http.Get(server.URL + "/")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "video.mp4") || !strings.Contains(string(body), "sub/") {
		t.Fatal("directory listing missing entries")
	}

	resp, _ = http.Get(server.URL + "/../outside.txt")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "secret") {
		t.Fatal("path traversal escaped the document root")
	}

	req, _ = http.NewRequest("PUT", server.URL+"/video.mp4", strings.NewReader("x"))
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatal("write method accepted")
	}
}
