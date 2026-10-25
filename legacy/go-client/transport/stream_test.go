package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestLargeFramesAndHalfClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c := New(ws)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		data, err := io.ReadAll(c)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = c.Write(data)
		_ = c.CloseWrite()
	}))
	defer server.Close()
	ws, _, err := websocket.Dial(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ws)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("frame"), 100000)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("stream: %d bytes, %v", len(response), err)
	}
}

func TestTruncatedRawFrameIsRejected(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		var header [5]byte
		binary.BigEndian.PutUint32(header[1:], 1024)
		_, _ = client.Write(header[:])
		_, _ = client.Write([]byte("short"))
	}()
	_, err := Wrap(server).WriteTo(io.Discard)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame: %v", err)
	}
}
