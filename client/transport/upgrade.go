package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
)

type upgradeConn struct {
	net.Conn
	body io.ReadWriteCloser
}

func (c *upgradeConn) Read(p []byte) (int, error)  { return c.body.Read(p) }
func (c *upgradeConn) Write(p []byte) (int, error) { return c.body.Write(p) }
func (c *upgradeConn) Close() error                { return c.body.Close() }

// DialUpgrade uses the pinned HTTPS client supplied by the tunnel dialer.
// A 101 response transfers socket ownership out of net/http's connection pool.
func DialUpgrade(ctx context.Context, client *http.Client, address, host string) (*Stream, error) {
	if client == nil {
		return nil, errors.New("direct stream requires a configured HTTPS client")
	}
	address = strings.Replace(strings.Replace(address, "wss://", "https://", 1), "ws://", "http://", 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", Subprotocol)
	if host != "" {
		req.Host = host
	}
	var conn net.Conn
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { conn = info.Conn }}))
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), Subprotocol) {
		response.Body.Close()
		return nil, fmt.Errorf("direct stream upgrade: HTTP %d", response.StatusCode)
	}
	body, ok := response.Body.(io.ReadWriteCloser)
	if !ok || conn == nil {
		response.Body.Close()
		return nil, errors.New("HTTP transport did not transfer the stream socket")
	}
	return Wrap(&upgradeConn{Conn: conn, body: body}), nil
}
