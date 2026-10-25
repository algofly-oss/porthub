package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	downloadBytes = 8 << 20
	uploadBytes   = 4 << 20
)

var speedClient = &http.Client{Transport: &http.Transport{DisableCompression: true, Proxy: http.ProxyFromEnvironment}}

// Measure returns a route's relay throughput in Mbit/s: the harmonic mean of
// a download and an upload, since relayed traffic flows both ways.
func Measure(ctx context.Context, server, user, credential string) (float64, error) {
	base := strings.TrimRight(server, "/") + SpeedPath
	run := func(method string, body io.Reader, want int64) (float64, error) {
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		url := base
		if method == http.MethodGet {
			url = fmt.Sprintf("%s?bytes=%d", base, want)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-Relay-User", user)
		req.Header.Set("X-Relay-Credential", credential)
		start := time.Now()
		resp, err := speedClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("speed test HTTP %d", resp.StatusCode)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		if method == http.MethodPost {
			n = want
		}
		if err != nil && n == 0 {
			return 0, err
		}
		return float64(n) * 8 / time.Since(start).Seconds() / 1e6, nil
	}
	down, err := run(http.MethodGet, nil, downloadBytes)
	if err != nil {
		return 0, err
	}
	up, err := run(http.MethodPost, bytes.NewReader(make([]byte, uploadBytes)), uploadBytes)
	if err != nil {
		return 0, err
	}
	if down <= 0 || up <= 0 {
		return 0, nil
	}
	return 2 * down * up / (down + up), nil
}
