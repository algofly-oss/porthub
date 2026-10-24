package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/api/internal/config"
	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/store"
	"github.com/coder/websocket"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type auditCollection struct {
	Count       int    `json:"count"`
	Fingerprint string `json:"fingerprint"`
}
type auditProbe struct {
	Path       string  `json:"path"`
	Account    string  `json:"account,omitempty"`
	Status     int     `json:"status"`
	DurationMS float64 `json:"duration_ms"`
}
type auditReport struct {
	CapturedAt       time.Time                  `json:"captured_at"`
	Collections      map[string]auditCollection `json:"collections"`
	MachinesOnline   int                        `json:"machines_online"`
	PrivateInstalled int                        `json:"private_installed"`
	PrivateOnline    int                        `json:"private_online"`
	AccountsChecked  int                        `json:"accounts_checked"`
	Probes           []auditProbe               `json:"probes"`
	Warnings         []string                   `json:"warnings"`
	Problems         []string                   `json:"problems"`
}

// Fingerprints contain configuration only. Credentials and session tokens are
// never written to the audit report; runtime heartbeats do not affect comparison.
var auditFields = map[string][]string{
	"users":             {"_id", "username", "name", "is_admin"},
	"machines":          {"_id", "user_id", "name", "aliases", "hostname_override", "enabled", "deletion_pending", "group_ids", "private_owner_id", "private_owner_revoked", "client_setup_public_base_url", "client_setup_rathole_server_address", "client_setup_service_domain"},
	"connections":       {"_id", "user_id", "machine_id", "internal_ip", "internal_port", "external_port", "service_name", "service_description", "enabled", "firewall"},
	"machine_groups":    {"_id", "user_id", "name", "sort_order", "user_ids"},
	"traffic_routes":    {"_id", "user_id", "name", "hosts", "group", "description", "target_mode", "target_url", "entry_points", "service", "connection", "enabled", "tls", "middlewares"},
	"access_rulebooks":  {"_id", "user_id", "name", "enabled", "rules", "group_id"},
	"private_peers":     {"_id", "workspace_id", "machine_id", "owner_id", "ip", "enabled", "hostname"},
	"private_networks":  {"_id", "cidr", "dns_suffix"},
	"workspace_members": {"_id", "workspace_id", "user_id", "role"},
}

func fingerprint(docs []core.Doc, fields []string) auditCollection {
	rows := make([]string, 0, len(docs))
	for _, doc := range docs {
		selected := map[string]any{}
		for _, field := range fields {
			if value, ok := doc[field]; ok {
				selected[field] = core.JSON(value)
			}
		}
		encoded, _ := json.Marshal(selected)
		rows = append(rows, string(encoded))
	}
	sort.Strings(rows)
	sum := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return auditCollection{Count: len(docs), Fingerprint: hex.EncodeToString(sum[:])}
}

func compareAudit(current, before auditReport) []string {
	problems := []string{}
	for name, old := range before.Collections {
		if current.Collections[name] != old {
			problems = append(problems, "configuration changed: "+name)
		}
	}
	if current.MachinesOnline < before.MachinesOnline {
		problems = append(problems, "fewer machines online than baseline")
	}
	if current.PrivateInstalled < before.PrivateInstalled {
		problems = append(problems, "fewer private clients installed than baseline")
	}
	if current.PrivateOnline < before.PrivateOnline {
		problems = append(problems, "fewer private clients online than baseline")
	}
	sort.Strings(problems)
	return problems
}

func auditBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("audit base URL must be HTTP(S) on loopback")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("audit base URL must be on loopback; account sessions stay on this host")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("audit base URL must not have a path")
	}
	return strings.TrimRight(raw, "/"), nil
}

func runAudit(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	base := flags.String("base-url", "http://127.0.0.1:47080", "running API on loopback")
	baseline := flags.String("baseline", "", "compare configuration with an earlier JSON report")
	if err := flags.Parse(args); err != nil {
		return err
	}
	endpoint, err := auditBase(*base)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, closeDB, err := store.Connect(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		return err
	}
	defer closeDB()
	app := &core.App{DB: db, Cfg: cfg}
	report := auditReport{CapturedAt: core.Now(), Collections: map[string]auditCollection{}, Probes: []auditProbe{}, Problems: []string{}, Warnings: []string{}}
	for collection, fields := range auditFields {
		docs, err := app.FindAll(ctx, collection, bson.M{})
		if err != nil {
			return fmt.Errorf("audit collection %s: %w", collection, err)
		}
		report.Collections[collection] = fingerprint(docs, fields)
		for _, doc := range docs {
			if collection == "machines" && !core.IsFalse(doc, "enabled") && !core.Truthy(doc, "deletion_pending") && app.IsOnline(doc) {
				report.MachinesOnline++
			}
			if collection == "private_peers" && core.Truthy(doc, "enabled") {
				if core.Truthy(doc, "credential_hash") {
					report.PrivateInstalled++
				}
				if last, ok := core.AsTime(doc["last_seen_at"]); ok && report.CapturedAt.Sub(last) < 40*time.Second {
					report.PrivateOnline++
				}
			}
		}
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	probe := func(path, account, token string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+path, nil)
		if token != "" {
			req.AddCookie(&http.Cookie{Name: cfg.SessionCookie, Value: token})
		}
		result := auditProbe{Path: path, Account: account}
		started := time.Now()
		response, err := client.Do(req)
		if err == nil {
			result.Status = response.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<20))
			response.Body.Close()
		}
		result.DurationMS = float64(time.Since(started).Microseconds()) / 1000
		if result.Status != 200 {
			report.Problems = append(report.Problems, fmt.Sprintf("probe %s account %s: HTTP %d", path, account, result.Status))
		}
		report.Probes = append(report.Probes, result)
	}
	for _, path := range []string{"/api/ping", "/api/auth/settings", "/api/openapi.json", "/api/docs"} {
		probe(path, "", "")
	}
	sessions, err := app.FindAll(ctx, "user_sessions", bson.M{"revoked_at": nil, "$or": bson.A{bson.M{"expires_at": nil}, bson.M{"expires_at": bson.M{"$gt": core.Now()}}}}, options.Find().SetSort(core.Sort("_id", 1)))
	if err != nil {
		return err
	}
	checked := map[string]bool{}
	for _, session := range sessions {
		account := core.IDString(session["user_id"])
		if account == "" || checked[account] {
			continue
		}
		checked[account] = true
		report.AccountsChecked++
		socketProbe := auditProbe{Path: "/socket.io/ (authenticated status snapshot)", Account: account}
		if err := auditSocket(ctx, endpoint, cfg.SessionCookie, core.Str(session, "_id")); err != nil {
			report.Problems = append(report.Problems, "Socket.IO status snapshot failed for account "+account)
		} else {
			socketProbe.Status = http.StatusSwitchingProtocols
		}
		report.Probes = append(report.Probes, socketProbe)
		for _, path := range []string{"/api/auth/me", "/api/machines/list", "/api/groups/list", "/api/connections/list", "/api/traffic-routes/list", "/api/access/snapshot"} {
			probe(path, account, core.Str(session, "_id"))
		}
	}
	if report.AccountsChecked == 0 {
		report.Warnings = append(report.Warnings, "authenticated probes skipped: no active account session available")
	}
	if *baseline != "" {
		data, err := os.ReadFile(*baseline)
		if err != nil {
			return err
		}
		var before auditReport
		if err := json.Unmarshal(data, &before); err != nil {
			return err
		}
		if len(before.Collections) == 0 {
			return fmt.Errorf("baseline has no configuration fingerprints")
		}
		report.Problems = append(report.Problems, compareAudit(report, before)...)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if len(report.Problems) > 0 {
		return fmt.Errorf("audit found %d problem(s)", len(report.Problems))
	}
	return nil
}

// Exercise the same WebSocket-only Socket.IO protocol as the dashboard. This
// checks authentication and an actual application event, not just an upgrade.
func auditSocket(parent context.Context, endpoint, cookie, token string) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	address := strings.Replace(strings.Replace(endpoint, "https://", "wss://", 1), "http://", "ws://", 1) + "/socket.io/?EIO=4&transport=websocket"
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.AddCookie(&http.Cookie{Name: cookie, Value: token})
	conn, _, err := websocket.Dial(ctx, address, &websocket.DialOptions{HTTPHeader: req.Header, HTTPClient: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(8 << 20)
	_, frame, err := conn.Read(ctx)
	if err != nil || len(frame) == 0 || frame[0] != '0' {
		return fmt.Errorf("missing Engine.IO open")
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("40")); err != nil {
		return err
	}
	for {
		_, frame, err = conn.Read(ctx)
		if err != nil {
			return err
		}
		if string(frame) == "2" {
			if err := conn.Write(ctx, websocket.MessageText, []byte("3")); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(string(frame), "44") {
			return fmt.Errorf("Socket.IO connection rejected")
		}
		if strings.HasPrefix(string(frame), "40") {
			if err := conn.Write(ctx, websocket.MessageText, []byte(`42["/cts/machines/status-snapshot",{}]`)); err != nil {
				return err
			}
		}
		if strings.HasPrefix(string(frame), "42") {
			var event []json.RawMessage
			if json.Unmarshal(frame[2:], &event) != nil || len(event) < 2 {
				continue
			}
			var name string
			_ = json.Unmarshal(event[0], &name)
			if name == "/stc/machines/status-snapshot" {
				var snapshot struct {
					Machines []json.RawMessage `json:"machines"`
				}
				if err := json.Unmarshal(event[1], &snapshot); err != nil {
					return err
				}
				if snapshot.Machines == nil {
					return fmt.Errorf("missing machines in status snapshot")
				}
				return nil
			}
		}
	}
}
