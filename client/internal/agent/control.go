package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/client/internal/mesh"
	"github.com/algofly-oss/porthub/client/internal/policy"
)

type Config struct {
	Server            string   `json:"server"`
	PeerID            string   `json:"peer_id"`
	Token             string   `json:"token"`
	Workspace         string   `json:"workspace"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http_for_tests,omitempty"`
	FallbackServers   []string `json:"fallback_servers,omitempty"`
	profilePath       string
}
type Signal struct {
	ID          string           `json:"id,omitempty"`
	From        string           `json:"from,omitempty"`
	To          string           `json:"to,omitempty"`
	Session     string           `json:"session"`
	Description mesh.Description `json:"description"`
}
type syncRequest struct {
	PeerID      string            `json:"peer_id"`
	Token       string            `json:"token"`
	Fingerprint string            `json:"fingerprint"`
	Instance    string            `json:"instance"`
	Signals     []Signal          `json:"signals"`
	Acks        []string          `json:"acks"`
	Paths       map[string]string `json:"paths"`
}
type syncResponse struct {
	Snapshot   policy.Snapshot  `json:"snapshot"`
	Signals    []Signal         `json:"signals"`
	ICEServers []mesh.ICEServer `json:"ice_servers"`
	// Extra base URLs of the same gateway (e.g. direct, bypassing a CDN);
	// the agent measures each and relays through the fastest.
	RelayRoutes      []string `json:"relay_routes"`
	ControlFallbacks []string `json:"control_fallback_urls"`
}
type Control struct {
	config      Config
	http        *http.Client
	lastGood    string
	preferUntil time.Time
}
type Rejected struct{ Code int }

func (r Rejected) Error() string {
	return fmt.Sprintf("private control request rejected (HTTP %d)", r.Code)
}

func NewControl(c Config) (*Control, error) {
	u, err := url.Parse(c.Server)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(c.AllowInsecureHTTP && u.Scheme == "http")) {
		return nil, errors.New("a valid HTTPS PortHub server URL is required")
	}
	c.Server = strings.TrimRight(c.Server, "/")
	for _, base := range c.FallbackServers {
		if !validFallback(base) {
			return nil, errors.New("invalid PortHub fallback URL")
		}
	}
	return &Control{config: c, http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func ReadConfig(path string) (Config, error) {
	var c Config
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return c, errors.New("client profile must be a regular file readable only by its owner (mode 0600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 65536))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&c); err != nil {
		return c, err
	}
	if c.PeerID == "" || len(c.Token) < 32 || c.Workspace == "" {
		return c, errors.New("incomplete private client profile")
	}
	_, err = NewControl(c)
	c.profilePath = path
	return c, err
}

func validFallback(base string) bool {
	u, err := url.Parse(base)
	return err == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Scheme == "http" || u.Scheme == "https")
}
func (c *Control) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	bases := append([]string{c.config.Server}, c.config.FallbackServers...)
	if c.lastGood != "" && time.Now().Before(c.preferUntil) {
		bases = append([]string{c.lastGood}, bases...)
	}
	seen := map[string]bool{}
	var last error
	for _, base := range bases {
		base = strings.TrimRight(base, "/")
		if seen[base] {
			continue
		}
		seen[base] = true
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		r, err := http.NewRequestWithContext(attempt, "POST", base+"/api/access/private/"+path, bytes.NewReader(b))
		if err != nil {
			cancel()
			return err
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(r)
		if err != nil {
			cancel()
			last = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if response.StatusCode == 200 {
			err = json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(out)
			response.Body.Close()
			cancel()
			if err != nil {
				return err
			}
			if base != c.lastGood || seen[c.config.Server] {
				c.preferUntil = time.Now().Add(30 * time.Second)
			}
			c.lastGood = base
			return nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		cancel()
		last = Rejected{response.StatusCode}
		if response.StatusCode < 500 && (response.StatusCode < 300 || response.StatusCode >= 400) {
			return last
		}
	}
	return last
}
func Bootstrap(ctx context.Context, server, ticket string, insecure bool) (Config, error) {
	c := Config{Server: server, AllowInsecureHTTP: insecure}
	control, err := NewControl(c)
	if err != nil {
		return c, err
	}
	err = control.post(ctx, "bootstrap", map[string]string{"ticket": ticket}, &c)
	return c, err
}
func (c *Control) sync(ctx context.Context, request syncRequest) (syncResponse, error) {
	var response syncResponse
	request.PeerID = c.config.PeerID
	request.Token = c.config.Token
	err := c.post(ctx, "sync", request, &response)
	if err == nil && (response.Snapshot.Workspace != c.config.Workspace || response.Snapshot.Self != c.config.PeerID) {
		return response, errors.New("control response belongs to a different private identity")
	}
	if err == nil && response.ControlFallbacks != nil {
		fallbacks := []string{}
		for _, base := range response.ControlFallbacks {
			if validFallback(base) && !slices.Contains(fallbacks, base) {
				fallbacks = append(fallbacks, base)
			}
		}
		if !slices.Equal(c.config.FallbackServers, fallbacks) {
			c.config.FallbackServers = fallbacks
			if c.config.profilePath != "" {
				if e := c.persist(); e != nil {
					return response, e
				}
			}
		}
	}
	return response, err
}

func (c *Control) persist() error {
	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.config.profilePath), ".porthub-profile-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), c.config.profilePath)
}
