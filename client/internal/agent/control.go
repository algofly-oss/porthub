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
	"strings"
	"time"

	"github.com/algofly-oss/porthub/client/internal/policy"
	"github.com/pion/webrtc/v4"
)

type Config struct {
	Server            string `json:"server"`
	PeerID            string `json:"peer_id"`
	Token             string `json:"token"`
	Workspace         string `json:"workspace"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http_for_tests,omitempty"`
}
type Signal struct {
	ID          string                    `json:"id,omitempty"`
	From        string                    `json:"from,omitempty"`
	To          string                    `json:"to,omitempty"`
	Session     string                    `json:"session"`
	Description webrtc.SessionDescription `json:"description"`
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
	Snapshot   policy.Snapshot    `json:"snapshot"`
	Signals    []Signal           `json:"signals"`
	ICEServers []webrtc.ICEServer `json:"ice_servers"`
}
type Control struct {
	config Config
	http   *http.Client
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
	return c, err
}
func (c *Control) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", c.config.Server+"/api/access/private/"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return Rejected{response.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(out)
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
	return response, err
}
