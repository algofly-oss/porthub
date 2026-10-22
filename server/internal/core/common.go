package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/algofly-oss/porthub/server/internal/auth"
	"github.com/algofly-oss/porthub/server/internal/config"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// App is shared by every route group and background worker.
type App struct {
	DB       *mongo.Database
	Cfg      config.Config
	Sessions *auth.Sessions
	// Events delivers Socket.IO events to browsers (set by the socket hub).
	Events Events
	// Rebuild coalesces Rathole/Traefik config rewrites.
	rebuildMu sync.Mutex
}

// Events is implemented by the Socket.IO hub. Room "" means the user room.
type Events interface {
	Emit(event string, data any, room string)
	MachineStatusChanged(ctx context.Context, machine Doc)
	MachineConfigChanged(ctx context.Context, machineID string)
	DisconnectMachine(machineID string)
	SetCachedStatus(machineID string, online bool)
	RemoveCachedStatus(machineID string)
	LogLines(ctx context.Context, machine Doc, lines []string, source string)
	LogStreamRequested(machineID string) bool
}

func (a *App) C(name string) *mongo.Collection { return a.DB.Collection(name) }

// FindOne returns the document or nil when none matches.
func (a *App) FindOne(ctx context.Context, coll string, filter any, opts ...options.Lister[options.FindOneOptions]) (Doc, error) {
	var d Doc
	err := a.C(coll).FindOne(ctx, filter, opts...).Decode(&d)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return d, err
}

// FindAll returns every matching document.
func (a *App) FindAll(ctx context.Context, coll string, filter any, opts ...options.Lister[options.FindOptions]) ([]Doc, error) {
	cur, err := a.C(coll).Find(ctx, filter, opts...)
	if err != nil {
		return nil, err
	}
	out := []Doc{}
	err = cur.All(ctx, &out)
	return out, err
}

// Sort builds an ordered sort spec: Sort("external_port", 1, "_id", 1).
func Sort(pairs ...any) bson.D {
	d := bson.D{}
	for i := 0; i+1 < len(pairs); i += 2 {
		d = append(d, bson.E{Key: pairs[i].(string), Value: pairs[i+1]})
	}
	return d
}

// ParseOID mirrors parse_object_id: 400 with detail when invalid.
func ParseOID(value, detail string) (bson.ObjectID, error) {
	id, err := bson.ObjectIDFromHex(value)
	if value == "" || err != nil {
		return id, httpapi.Fail(400, detail)
	}
	return id, nil
}

// ValidOID mirrors ObjectId.is_valid for strings.
func ValidOID(value string) bool {
	_, err := bson.ObjectIDFromHex(value)
	return err == nil
}

// UserID mirrors authenticate_user: the session's user id or 400.
func (a *App) UserID(ctx context.Context) (string, error) {
	id := a.Sessions.UserID(ctx, a.Sessions.Token(httpapi.Request(ctx)))
	if id == "" {
		return "", httpapi.Fail(400, "User not logged in")
	}
	return id, nil
}

// User mirrors get_authenticated_user.
func (a *App) User(ctx context.Context) (Doc, error) {
	id, err := a.UserID(ctx)
	if err != nil {
		return nil, err
	}
	oid, err := ParseOID(id, "User not logged in")
	if err != nil {
		return nil, err
	}
	user, err := a.FindOne(ctx, "users", bson.M{"_id": oid})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, httpapi.Fail(400, "User not logged in")
	}
	return user, nil
}

// MachineGroupIDs mirrors get_machine_group_object_ids.
func MachineGroupIDs(machine Doc) []bson.ObjectID {
	out := []bson.ObjectID{}
	seen := map[bson.ObjectID]bool{}
	for _, item := range List(machine, "group_ids") {
		if id, ok := AsOID(item); ok && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) > 0 {
		return out
	}
	if id, ok := AsOID(machine["group_id"]); ok {
		return []bson.ObjectID{id}
	}
	return out
}

// SplitMachineNames mirrors split_machine_names: first name plus aliases.
func SplitMachineNames(value string) (string, []string, error) {
	names := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[strings.ToLower(part)] {
			continue
		}
		seen[strings.ToLower(part)] = true
		if r := []rune(part); len(r) > 64 {
			part = string(r[:64])
		}
		names = append(names, part)
	}
	if len(names) == 0 {
		return "", nil, httpapi.Fail(400, "Machine name is required")
	}
	if len(names) > 11 {
		return "", nil, httpapi.Fail(400, "Use at most 10 aliases")
	}
	return names[0], names[1:], nil
}

// ResolveMachineHostname mirrors resolve_machine_hostname.
func ResolveMachineHostname(machine Doc) string {
	for _, key := range []string{"hostname_override", "client_hostname", "hostname"} {
		if v := Trim(machine, key); v != "" {
			return v
		}
	}
	return ""
}

// ConnectionStatus mirrors get_machine_connection_status.
func (a *App) ConnectionStatus(machine Doc) string {
	if IsFalse(machine, "enabled") {
		return "disabled"
	}
	seen, ok := Time(machine, "last_seen_at")
	if !ok || seen.Before(time.Now().UTC().Add(-a.Cfg.MachineOnlineTTL)) {
		return "offline"
	}
	if Truthy(machine, "auth_required") {
		return "auth_required"
	}
	return "online"
}

func (a *App) IsOnline(machine Doc) bool {
	s := a.ConnectionStatus(machine)
	return s == "online" || s == "auth_required"
}

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandomString(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(tokenAlphabet)))
	for i := range b {
		v, _ := rand.Int(rand.Reader, max)
		b[i] = tokenAlphabet[v.Int64()]
	}
	return string(b)
}

// GenerateMachineToken mirrors generate_machine_token (48 chars, unique).
func (a *App) GenerateMachineToken(ctx context.Context) (string, error) {
	for {
		token := RandomString(48)
		n, err := a.C("machines").CountDocuments(ctx, bson.M{"token": token}, options.Count().SetLimit(1))
		if err != nil {
			return "", err
		}
		if n == 0 {
			return token, nil
		}
	}
}

var clientVersion struct {
	sync.Mutex
	mtime   time.Time
	size    int64
	version string
}

// ClientScriptPath is the shell client served to machines.
func (a *App) ClientScriptPath() string {
	return filepath.Join(a.Cfg.ClientAssetsDir, "porthub-client.sh")
}

// ClientVersion mirrors get_client_version: sha256 of the client script, 12 hex.
func (a *App) ClientVersion() string {
	path := a.ClientScriptPath()
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	clientVersion.Lock()
	defer clientVersion.Unlock()
	if info.ModTime().Equal(clientVersion.mtime) && info.Size() == clientVersion.size && clientVersion.version != "" {
		return clientVersion.version
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	clientVersion.mtime, clientVersion.size, clientVersion.version = info.ModTime(), info.Size(), hex.EncodeToString(sum[:])[:12]
	return clientVersion.version
}

// FirewallPolicy mirrors get_stored_connection_firewall_policy.
func FirewallPolicy(connection Doc) map[string]any {
	fw, ok := Map(connection, "firewall")
	if !ok {
		return map[string]any{"is_public": true, "allowed_ips": []any{}}
	}
	ips := []any{}
	for _, ip := range List(fw, "allowed_ips") {
		ips = append(ips, IDString(ip))
	}
	public := true
	if v, ok := fw["is_public"]; ok {
		public = truthy(v)
	}
	return map[string]any{"is_public": public, "allowed_ips": ips}
}

func valueOr(d Doc, key string, fallback any) any {
	if v, ok := d[key]; ok {
		return v
	}
	return fallback
}

// SerializeMachine mirrors router.common.serialize_machine.
func (a *App) SerializeMachine(machine Doc) map[string]any {
	status := a.ConnectionStatus(machine)
	clientVersion := Trim(machine, "client_version")
	latest := a.ClientVersion()
	requestID := Trim(machine, "client_update_request_id")
	handled := Trim(machine, "client_update_last_handled_request_id")
	groups := []any{}
	for _, id := range MachineGroupIDs(machine) {
		groups = append(groups, id.Hex())
	}
	aliases := []any{}
	for _, alias := range List(machine, "aliases") {
		aliases = append(aliases, IDString(alias))
	}
	return map[string]any{
		"_id":                                 IDString(machine["_id"]),
		"user_id":                             IDString(machine["user_id"]),
		"name":                                JSON(valueOr(machine, "name", "")),
		"aliases":                             aliases,
		"hostname":                            ResolveMachineHostname(machine),
		"client_hostname":                     Trim(machine, "client_hostname"),
		"hostname_override":                   Trim(machine, "hostname_override"),
		"client_setup_public_base_url":        Trim(machine, "client_setup_public_base_url"),
		"client_setup_rathole_server_address": Trim(machine, "client_setup_rathole_server_address"),
		"client_setup_service_domain":         Trim(machine, "client_setup_service_domain"),
		"group_ids":                           groups,
		"enabled":                             JSON(valueOr(machine, "enabled", true)),
		"telegram_alerts_excluded":            Truthy(machine, "telegram_alerts_excluded"),
		"local_ip":                            JSON(valueOr(machine, "local_ip", valueOr(machine, "ip_address", ""))),
		"public_ip":                           JSON(valueOr(machine, "public_ip", "")),
		"token":                               JSON(valueOr(machine, "token", "")),
		"is_active":                           status == "online" || status == "auth_required",
		"connection_status":                   status,
		"auth_required":                       status == "auth_required",
		"client_version":                      clientVersion,
		"latest_client_version":               latest,
		"client_update_available":             clientVersion != "" && clientVersion != latest,
		"client_update_requested":             requestID != "" && requestID != handled,
		"client_update_target_version":        Trim(machine, "client_update_target_version"),
		"client_update_request_id":            requestID,
		"client_update_requested_at":          JSON(machine["client_update_requested_at"]),
		"client_updated_at":                   JSON(machine["client_updated_at"]),
		"last_seen_at":                        JSON(machine["last_seen_at"]),
		"created_at":                          JSON(machine["created_at"]),
		"updated_at":                          JSON(machine["updated_at"]),
	}
}

// InternalIP mirrors connection.get("internal_ip", connection.get("internalIp", "0.0.0.0")).
func InternalIP(connection Doc) any {
	return valueOr(connection, "internal_ip", valueOr(connection, "internalIp", "0.0.0.0"))
}

// SerializeConnection mirrors router.common.serialize_connection (machine may be nil).
func (a *App) SerializeConnection(connection, machine Doc) map[string]any {
	machineID := ""
	if Truthy(connection, "machine_id") {
		machineID = IDString(connection["machine_id"])
	}
	out := map[string]any{
		"_id":                           IDString(connection["_id"]),
		"user_id":                       IDString(connection["user_id"]),
		"machine_id":                    machineID,
		"service_name":                  JSON(valueOr(connection, "service_name", "")),
		"service_description":           JSON(valueOr(connection, "service_description", "")),
		"internal_ip":                   JSON(InternalIP(connection)),
		"internal_port":                 JSON(connection["internal_port"]),
		"external_port":                 JSON(connection["external_port"]),
		"enabled":                       JSON(valueOr(connection, "enabled", true)),
		"auto_refresh_enabled":          JSON(valueOr(connection, "auto_refresh_enabled", false)),
		"auto_refresh_interval_minutes": JSON(connection["auto_refresh_interval_minutes"]),
		"auto_refreshed_at":             JSON(connection["auto_refreshed_at"]),
		"auto_refresh_next_at":          JSON(connection["auto_refresh_next_at"]),
		"firewall":                      FirewallPolicy(connection),
		"created_at":                    JSON(connection["created_at"]),
		"updated_at":                    JSON(connection["updated_at"]),
	}
	if machine != nil {
		out["machine_name"] = JSON(valueOr(machine, "name", ""))
		out["machine_hostname"] = ResolveMachineHostname(machine)
		out["machine_local_ip"] = JSON(valueOr(machine, "local_ip", valueOr(machine, "ip_address", "")))
		out["machine_public_ip"] = JSON(valueOr(machine, "public_ip", ""))
		out["machine_enabled"] = JSON(valueOr(machine, "enabled", true))
		out["machine_is_active"] = a.IsOnline(machine)
		out["machine_connection_status"] = a.ConnectionStatus(machine)
	} else {
		out["machine_name"] = JSON(valueOr(connection, "host_name", ""))
		out["machine_hostname"] = JSON(valueOr(connection, "host_id", ""))
		out["machine_local_ip"] = JSON(valueOr(connection, "host_ip", ""))
		out["machine_public_ip"] = ""
		out["machine_enabled"] = true
		out["machine_is_active"] = false
		out["machine_connection_status"] = "unknown"
	}
	return out
}
