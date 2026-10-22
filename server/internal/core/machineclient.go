package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// HeaderError is an HTTPException with headers (machine deleted/disabled).
type HeaderError struct {
	httpapi.FastAPIError
	Headers http.Header `json:"-"`
}

func (e *HeaderError) GetHeaders() http.Header { return e.Headers }

var _ huma.HeadersError = (*HeaderError)(nil)

func machineGone() error {
	return &HeaderError{httpapi.FastAPIError{Status: 410, Detail: "Machine deleted"}, http.Header{"X-Porthub-Machine-Deleted": {"true"}}}
}

// AuthenticateMachine mirrors authenticate_machine.
func (a *App) AuthenticateMachine(ctx context.Context, machineID, token string) (Doc, error) {
	id, err := ParseOID(machineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := a.FindOne(ctx, "machines", bson.M{"_id": id, "token": token})
	if err != nil {
		return nil, err
	}
	if machine == nil || Truthy(machine, "deletion_pending") {
		return nil, machineGone()
	}
	if IsFalse(machine, "enabled") {
		return nil, &HeaderError{httpapi.FastAPIError{Status: 403, Detail: "Machine disabled"}, http.Header{"X-Porthub-Machine-Disabled": {"true"}}}
	}
	return machine, nil
}

// AuthenticateMachineForLogs mirrors authenticate_machine_for_logs (no token check).
func (a *App) AuthenticateMachineForLogs(ctx context.Context, machineID string) (Doc, error) {
	id, err := ParseOID(machineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := a.FindOne(ctx, "machines", bson.M{"_id": id})
	if err != nil {
		return nil, err
	}
	if machine == nil || Truthy(machine, "deletion_pending") {
		return nil, machineGone()
	}
	return machine, nil
}

// RequestClientIP mirrors get_request_client_ip.
func RequestClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if first := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); first != "" {
		return first
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RequestBaseURL mirrors str(request.base_url) without the trailing slash.
func RequestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); p != "" {
		scheme = p
	}
	return strings.TrimRight(scheme+"://"+r.Host, "/")
}

// Overrides are the client_setup_* values from the request query.
type Overrides map[string]string

var setupQuery = [][2]string{
	{"public_base_url", "client_setup_public_base_url"},
	{"rathole_server_address", "client_setup_rathole_server_address"},
	{"service_domain", "client_setup_service_domain"},
}

func RequestOverrides(r *http.Request) Overrides {
	o := Overrides{}
	if r == nil {
		return o
	}
	q := r.URL.Query()
	for _, kv := range setupQuery {
		if v := strings.TrimSpace(q.Get(kv[0])); v != "" {
			o[kv[1]] = v
		}
	}
	return o
}

func machineOverride(machine Doc, field string, o Overrides) string {
	if v := strings.TrimSpace(o[field]); v != "" {
		return v
	}
	if machine == nil {
		return ""
	}
	return Trim(machine, field)
}

func (a *App) PublicBaseURL(r *http.Request) string {
	if v := strings.TrimSpace(a.Cfg.PublicBaseURL); v != "" {
		return strings.TrimRight(v, "/")
	}
	if r == nil {
		return "http://localhost"
	}
	return RequestBaseURL(r)
}

func (a *App) MachinePublicBaseURL(machine Doc, r *http.Request, o Overrides) string {
	if v := machineOverride(machine, "client_setup_public_base_url", o); v != "" {
		return strings.TrimRight(v, "/")
	}
	return a.PublicBaseURL(r)
}

func (a *App) APIBaseURL(r *http.Request, machine Doc, o Overrides) string {
	return a.MachinePublicBaseURL(machine, r, o) + "/api"
}

func (a *App) SetupServiceDomain(machine Doc, o Overrides) string {
	if v := machineOverride(machine, "client_setup_service_domain", o); v != "" {
		return v
	}
	return a.Cfg.ServiceDomain
}

func (a *App) RatholeServerAddress(r *http.Request, machine Doc, o Overrides) string {
	if v := machineOverride(machine, "client_setup_rathole_server_address", o); v != "" {
		return v
	}
	if v := strings.TrimSpace(a.Cfg.RatholeServerAddress); v != "" {
		return v
	}
	host := "localhost"
	if u, err := url.Parse(a.MachinePublicBaseURL(machine, r, o)); err == nil && u.Hostname() != "" {
		host = strings.ToLower(u.Hostname())
	}
	return fmt.Sprintf("%s:%d", host, a.Cfg.RatholePort)
}

func MachineServiceKey(connection Doc) string {
	return fmt.Sprintf("porthub_%v_%s", JSON(Get(connection, "external_port", "port")), IDString(Get(connection, "_id", "service")))
}

func FormatLocalAddress(host string, port any) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "0.0.0.0"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%v", host, JSON(port))
	}
	return fmt.Sprintf("%s:%v", host, JSON(port))
}

func (a *App) MachineConnections(ctx context.Context, machine Doc) ([]Doc, error) {
	return a.FindAll(ctx, "connections", bson.M{"machine_id": machine["_id"]}, options.Find().SetSort(Sort("external_port", 1, "_id", 1)))
}

// SerializeMachineConnection mirrors serialize_machine_connection.
func SerializeMachineConnection(connection, machine Doc) map[string]any {
	ip := InternalIP(connection)
	ipStr, _ := ip.(string)
	if ipStr == "" && ip != nil {
		ipStr = pyStr(ip)
	}
	return map[string]any{
		"_id":                 IDString(connection["_id"]),
		"machine_id":          IDString(machine["_id"]),
		"service_key":         MachineServiceKey(connection),
		"service_name":        JSON(Get(connection, "service_name", "")),
		"service_description": JSON(Get(connection, "service_description", "")),
		"internal_ip":         JSON(ip),
		"internal_port":       JSON(connection["internal_port"]),
		"external_port":       JSON(connection["external_port"]),
		"enabled":             JSON(Get(connection, "enabled", true)),
		"local_address":       FormatLocalAddress(ipStr, connection["internal_port"]),
	}
}

// MachineConfigVersion mirrors build_machine_config_version (same digest).
func MachineConfigVersion(machine Doc, connections []Doc) string {
	conns := []any{}
	for _, c := range connections {
		var updated any
		if t, ok := Time(c, "updated_at"); ok {
			updated = JSON(t)
		}
		conns = append(conns, map[string]any{
			"_id":                 IDString(c["_id"]),
			"service_name":        JSON(Get(c, "service_name", "")),
			"service_description": JSON(Get(c, "service_description", "")),
			"internal_ip":         JSON(InternalIP(c)),
			"internal_port":       JSON(c["internal_port"]),
			"external_port":       JSON(c["external_port"]),
			"enabled":             JSON(Get(c, "enabled", true)),
			"updated_at":          updated,
		})
	}
	payload := map[string]any{
		"machine_id":                          IDString(machine["_id"]),
		"token":                               JSON(Get(machine, "token", "")),
		"enabled":                             truthy(Get(machine, "enabled", true)),
		"client_setup_rathole_server_address": machineOverride(machine, "client_setup_rathole_server_address", nil),
		"connections":                         conns,
	}
	sum := sha256.Sum256([]byte(PyDumps(payload)))
	return hex.EncodeToString(sum[:])
}

func (a *App) RenderClientTOML(machine Doc, connections []Doc, r *http.Request, o Overrides) string {
	lines := []string{managedHeader, "[client]", `remote_addr = "` + a.RatholeServerAddress(r, machine, o) + `"`, ""}
	for _, c := range connections {
		if IsFalse(c, "enabled") {
			continue
		}
		s := SerializeMachineConnection(c, machine)
		lines = append(lines, "[client.services."+s["service_key"].(string)+"]", `token = "`+Str(machine, "token")+`"`, `local_addr = "`+s["local_address"].(string)+`"`, "")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), " \t\n") + "\n"
}

func withSetupQuery(u string, o Overrides) string {
	q := url.Values{}
	for _, kv := range setupQuery {
		if v := strings.TrimSpace(o[kv[1]]); v != "" {
			q.Set(kv[0], o[kv[1]])
		}
	}
	if len(q) == 0 {
		return u
	}
	// urlencode keeps insertion order; emit in the Python dict order.
	parts := []string{}
	for _, kv := range setupQuery {
		if v := q.Get(kv[0]); v != "" {
			parts = append(parts, url.QueryEscape(kv[0])+"="+url.QueryEscape(v))
		}
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + strings.Join(parts, "&")
}

// MachineEndpoints mirrors build_machine_endpoints.
func (a *App) MachineEndpoints(machine Doc, r *http.Request) map[string]string {
	o := RequestOverrides(r)
	api := a.APIBaseURL(r, machine, o)
	id, token := IDString(machine["_id"]), Str(machine, "token")
	base := fmt.Sprintf("%s/machines/%s/%s", api, id, token)
	creds := "?machine_id=" + id + "&token=" + token
	e := map[string]string{
		"auth":                  api + "/machines/client/auth",
		"sync":                  api + "/machines/client/sync",
		"config":                api + "/machines/client/config" + creds,
		"config_toml":           api + "/machines/client/config.toml" + creds,
		"changes":               api + "/machines/client/changes" + creds,
		"changes_toml":          api + "/machines/client/changes.toml" + creds,
		"log_stream_status":     api + "/machines/client/log-stream" + creds,
		"log_stream_upload":     api + "/machines/client/logs",
		"legacy_sync":           api + "/machines/sync",
		"install_script":        api + "/install/" + token,
		"bootstrap_script":      base + "/install.sh",
		"client_cli":            base + "/downloads/porthub",
		"client_script":         base + "/client.sh",
		"rathole_x86_64":        base + "/downloads/rathole/x86_64",
		"rathole_darwin_x86_64": base + "/downloads/rathole/darwin_x86_64",
		"rathole_darwin_arm64":  base + "/downloads/rathole/darwin_arm64",
		"rathole_arm64":         base + "/downloads/rathole/arm64",
		"rathole_armhf":         base + "/downloads/rathole/armhf",
		"rathole_armv7":         base + "/downloads/rathole/armv7",
		"socket_path":           "/socket.io",
	}
	for _, k := range []string{"config", "config_toml", "changes", "changes_toml", "install_script", "bootstrap_script", "client_cli", "client_script",
		"rathole_x86_64", "rathole_darwin_x86_64", "rathole_darwin_arm64", "rathole_arm64", "rathole_armhf", "rathole_armv7"} {
		e[k] = withSetupQuery(e[k], o)
	}
	return e
}

// MachineConfigBundle mirrors build_machine_config_bundle (r may be nil).
func (a *App) MachineConfigBundle(ctx context.Context, machine Doc, r *http.Request) (map[string]any, error) {
	o := RequestOverrides(r)
	connections, err := a.MachineConnections(ctx, machine)
	if err != nil {
		return nil, err
	}
	serialized := []any{}
	for _, c := range connections {
		serialized = append(serialized, SerializeMachineConnection(c, machine))
	}
	return map[string]any{
		"version":                MachineConfigVersion(machine, connections),
		"machine_id":             IDString(machine["_id"]),
		"machine_name":           JSON(Get(machine, "name", "")),
		"hostname":               ResolveMachineHostname(machine),
		"enabled":                truthy(Get(machine, "enabled", true)),
		"rathole_server_address": a.RatholeServerAddress(r, machine, o),
		"service_domain":         a.SetupServiceDomain(machine, o),
		"connections":            serialized,
		"files":                  map[string]any{"client.toml": a.RenderClientTOML(machine, connections, r, o)},
		"generated_at":           JSON(Now()),
	}, nil
}

// SyncInput carries the optional values of sync_machine_runtime.
type SyncInput struct {
	Hostname, LocalIP, PublicIP, ClientVersion, HandledRequestID string
}

// SyncMachineRuntime mirrors sync_machine_runtime and returns the updated machine.
func (a *App) SyncMachineRuntime(ctx context.Context, machine Doc, r *http.Request, in SyncInput) (Doc, error) {
	now := Now()
	publicIP := strings.TrimSpace(in.PublicIP)
	if publicIP == "" {
		publicIP = Str(machine, "public_ip")
	}
	if publicIP == "" {
		publicIP = RequestClientIP(r)
	}
	version := strings.TrimSpace(in.ClientVersion)
	handled := strings.TrimSpace(in.HandledRequestID)
	clientHostname := strings.TrimSpace(in.Hostname)
	effective := Trim(machine, "hostname_override")
	for _, v := range []string{clientHostname, Trim(machine, "client_hostname"), Trim(machine, "hostname")} {
		if effective == "" {
			effective = v
		}
	}
	storedClientHostname := clientHostname
	if storedClientHostname == "" {
		storedClientHostname = Trim(machine, "client_hostname")
	}
	set := bson.M{
		"hostname":        effective,
		"client_hostname": storedClientHostname,
		"local_ip":        strings.TrimSpace(in.LocalIP),
		"public_ip":       publicIP,
		"auth_required":   false,
		"last_seen_at":    now,
	}
	if handled != "" {
		set["client_update_last_handled_request_id"] = handled
	}
	if version != "" {
		set["client_version"] = version
		if handled != "" && handled == Trim(machine, "client_update_request_id") {
			set["client_update_target_version"] = ""
			set["client_updated_at"] = now
		} else if version == a.ClientVersion() {
			set["client_updated_at"] = now
		}
	}
	if _, err := a.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, bson.M{"$set": set}); err != nil {
		return nil, err
	}
	return a.FindOne(ctx, "machines", bson.M{"_id": machine["_id"]})
}

// TouchMachinePresence mirrors touch_machine_client_presence.
func (a *App) TouchMachinePresence(ctx context.Context, machine Doc, authRequired bool) (Doc, error) {
	if _, err := a.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]},
		bson.M{"$set": bson.M{"auth_required": authRequired, "last_seen_at": Now()}}); err != nil {
		return nil, err
	}
	return a.FindOne(ctx, "machines", bson.M{"_id": machine["_id"]})
}

// WaitForConfigChange mirrors wait_for_machine_config_change (nil on timeout).
func (a *App) WaitForConfigChange(ctx context.Context, machineID, token, since string, r *http.Request, timeout time.Duration) (map[string]any, error) {
	if timeout <= 0 || timeout > a.Cfg.LongPollTimeout {
		timeout = a.Cfg.LongPollTimeout
	}
	if timeout < time.Second {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	for !time.Now().After(deadline) {
		machine, err := a.AuthenticateMachine(ctx, machineID, token)
		if err != nil {
			return nil, err
		}
		bundle, err := a.MachineConfigBundle(ctx, machine, r)
		if err != nil {
			return nil, err
		}
		if bundle["version"] != since {
			return bundle, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(a.Cfg.LongPollInterval):
		}
	}
	return nil, nil
}
