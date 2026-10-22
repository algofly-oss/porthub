package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const managedHeader = "# Managed by PortHub. Manual changes will be overwritten."

var keyPattern = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

func utcISO() string {
	t := time.Now().UTC()
	return t.Format("2006-01-02T15:04:05") + fmt.Sprintf(".%06d+00:00", t.Nanosecond()/1000)
}

// writeAtomic replaces path through a temp file and touches it so file
// watchers (Rathole, Traefik) reload.
func writeAtomic(path, prefix, content string, touchDir bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("config target must be a file, but is a directory: %s", path)
	}
	tmp, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err = tmp.WriteString(content); err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
		return err
	}
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	if touchDir {
		_ = os.Chtimes(dir, now, now)
	}
	return nil
}

// --- Rathole server.toml (shared/rathole_config.py) ---

func ServiceKey(connection Doc) string {
	id := strings.Trim(keyPattern.ReplaceAllString(IDString(Get(connection, "_id", "service")), "_"), "_")
	if id == "" {
		id = "service"
	}
	return fmt.Sprintf("porthub_%v_%s", Get(connection, "external_port", "port"), id)
}

type ratholeService struct {
	key, token string
	port       any
}

func (a *App) renderServerTOML(services []ratholeService, source string) string {
	lines := []string{
		managedHeader,
		"# source: " + source,
		"# generated_at_utc: " + utcISO(),
		fmt.Sprintf("# services_count: %d", len(services)),
		"[server]",
		fmt.Sprintf(`bind_addr = "0.0.0.0:%d"`, a.Cfg.RatholePort),
		"",
		"[server.services." + a.Cfg.RatholeDummyName + "]",
		`token = "` + a.Cfg.RatholeDummyToken + `"`,
		`bind_addr = "` + a.Cfg.RatholeDummyBind + `"`,
		"",
	}
	for _, s := range services {
		lines = append(lines, "[server.services."+s.key+"]", `token = "`+s.token+`"`, fmt.Sprintf(`bind_addr = "0.0.0.0:%v"`, s.port), "")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), " \t\n") + "\n"
}

func IsDummyOnlyConfig(content string) bool {
	return strings.Contains(content, "[server.services.dummy]") && !strings.Contains(content, "[server.services.porthub_")
}

func (a *App) WriteBaseServerTOML() error {
	return writeAtomic(a.Cfg.RatholeConfigPath, ".server.toml.tmp-", a.renderServerTOML(nil, "bootstrap"), false)
}

// RebuildServerTOML mirrors rebuild_server_toml.
func (a *App) RebuildServerTOML(ctx context.Context, allowEmpty bool) error {
	a.rebuildMu.Lock()
	defer a.rebuildMu.Unlock()
	machines, err := a.FindAll(ctx, "machines", bson.M{"enabled": bson.M{"$ne": false}, "token": bson.M{"$nin": bson.A{nil, ""}}})
	if err != nil {
		return err
	}
	byID := map[any]Doc{}
	ids := bson.A{}
	for _, m := range machines {
		byID[m["_id"]] = m
		ids = append(ids, m["_id"])
	}
	var services []ratholeService
	if len(ids) > 0 {
		connections, err := a.FindAll(ctx, "connections", bson.M{"enabled": bson.M{"$ne": false}, "machine_id": bson.M{"$in": ids}},
			options.Find().SetSort(Sort("external_port", 1, "_id", 1)))
		if err != nil {
			return err
		}
		for _, c := range connections {
			m := byID[c["machine_id"]]
			if m == nil {
				continue
			}
			services = append(services, ratholeService{ServiceKey(c), Str(m, "token"), JSON(c["external_port"])})
		}
	}
	path := a.Cfg.RatholeConfigPath
	if len(services) == 0 && !allowEmpty {
		if existing, err := os.ReadFile(path); err == nil && !IsDummyOnlyConfig(string(existing)) {
			log.Printf("Skipping dummy-only Rathole rewrite because an existing real config is present at %s", path)
			return nil
		}
	}
	if err := writeAtomic(path, ".server.toml.tmp-", a.renderServerTOML(services, "database-rebuild"), false); err != nil {
		return err
	}
	log.Printf("Rebuilt Rathole server config with %d services at %s", len(services), path)
	return nil
}

// --- Traefik dynamic config (shared/traffic_config.py) ---

func RouteKey(route Doc) string {
	id := strings.Trim(keyPattern.ReplaceAllString(IDString(Get(route, "_id", "route")), "_"), "_")
	if id == "" {
		id = "route"
	}
	return "porthub_traffic_" + id
}

func strList(v any, lower bool) []any {
	out := []any{}
	for _, item := range AsList(v) {
		s := strings.TrimSpace(pyStr(item))
		if lower {
			s = strings.ToLower(s)
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// pyStr mirrors str(value) for the scalar types stored in documents.
func pyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case bson.ObjectID:
		return x.Hex()
	}
	return fmt.Sprint(JSON(v))
}

func orNone(v any) any {
	if !truthy(v) {
		return nil
	}
	return JSON(v)
}

// SerializeTrafficRoute mirrors serialize_traffic_route_document.
func SerializeTrafficRoute(route Doc) map[string]any {
	mode := Trim(route, "target_mode")
	if Str(route, "target_mode") == "" {
		mode = "manual"
	}
	if mode == "" {
		mode = "manual"
	}
	entry := strList(route["entry_points"], false)
	if len(entry) == 0 {
		entry = []any{"web"}
	}
	return map[string]any{
		"_id":          IDString(route["_id"]),
		"user_id":      IDString(route["user_id"]),
		"name":         Trim(route, "name"),
		"group":        Trim(route, "group"),
		"description":  Trim(route, "description"),
		"hosts":        strList(route["hosts"], true),
		"target_mode":  mode,
		"target_url":   Trim(route, "target_url"),
		"enabled":      !IsFalse(route, "enabled"),
		"entry_points": entry,
		"connection":   orNone(route["connection"]),
		"created_at":   JSON(route["created_at"]),
		"updated_at":   JSON(route["updated_at"]),
	}
}

func yamlScalar(v string) string {
	b, _ := json.Marshal(v)
	// json.dumps escapes non-ASCII; Go's escapes HTML characters instead.
	s := strings.NewReplacer(`<`, "<", `>`, ">", `&`, "&").Replace(string(b))
	return asciiEscape(s)
}

func asciiEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteRune(r)
		case r > 0xFFFF:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// passHostHeaderOff mirrors should_disable_pass_host_header (serialized route).
func passHostHeaderOff(route map[string]any) bool {
	if strings.ToLower(strings.TrimSpace(route["target_mode"].(string))) != "manual" {
		return false
	}
	target := strings.TrimSpace(route["target_url"].(string))
	if target == "" {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	for _, h := range route["hosts"].([]any) {
		if h.(string) == host {
			return false
		}
	}
	return true
}

func renderTrafficConfig(routes []map[string]any, source string) string {
	lines := []string{managedHeader, "# source: " + source, "# generated_at_utc: " + utcISO(), fmt.Sprintf("# routes_count: %d", len(routes))}
	if len(routes) == 0 {
		return strings.Join(lines, "\n") + "\n"
	}
	lines = append(lines, "http:", "  routers:")
	for _, route := range routes {
		key := "porthub_traffic_" + strings.Trim(keyPattern.ReplaceAllString(route["_id"].(string), "_"), "_")
		hosts := []string{}
		for _, h := range route["hosts"].([]any) {
			hosts = append(hosts, "`"+h.(string)+"`")
		}
		rule := "Host(" + strings.Join(hosts, ",") + ")"
		lines = append(lines, "    "+key+":", "      entryPoints:")
		secure := false
		for _, e := range route["entry_points"].([]any) {
			lines = append(lines, "        - "+yamlScalar(e.(string)))
			secure = secure || e.(string) == "websecure"
		}
		lines = append(lines, "      rule: "+yamlScalar(rule), "      service: "+yamlScalar(key))
		if secure {
			lines = append(lines, "      tls: {}")
		} else {
			// Every proxy also answers HTTPS so Cloudflare "Full" zones work.
			lines = append(lines, "    "+key+"_tls:", "      entryPoints:", `        - "websecure"`,
				"      rule: "+yamlScalar(rule), "      service: "+yamlScalar(key), "      tls: {}")
		}
	}
	lines = append(lines, "  services:")
	for _, route := range routes {
		key := "porthub_traffic_" + strings.Trim(keyPattern.ReplaceAllString(route["_id"].(string), "_"), "_")
		pass := "true"
		if passHostHeaderOff(route) {
			pass = "false"
		}
		lines = append(lines, "    "+key+":", "      loadBalancer:", "        passHostHeader: "+pass, "        servers:",
			"          - url: "+yamlScalar(route["target_url"].(string)))
	}
	return strings.TrimRight(strings.Join(lines, "\n"), " \t\n") + "\n"
}

func (a *App) WriteBaseTrafficConfig() error {
	return writeAtomic(a.Cfg.TraefikConfigPath, ".traffic-routes.yml.tmp-", renderTrafficConfig(nil, "bootstrap"), true)
}

// RebuildTrafficConfig mirrors rebuild_traffic_config.
func (a *App) RebuildTrafficConfig(ctx context.Context) error {
	a.rebuildMu.Lock()
	defer a.rebuildMu.Unlock()
	routes, err := a.FindAll(ctx, "traffic_routes", bson.M{"enabled": bson.M{"$ne": false}}, options.Find().SetSort(Sort("created_at", 1, "_id", 1)))
	if err != nil {
		return err
	}
	serialized := make([]map[string]any, 0, len(routes))
	for _, r := range routes {
		serialized = append(serialized, SerializeTrafficRoute(r))
	}
	if err := writeAtomic(a.Cfg.TraefikConfigPath, ".traffic-routes.yml.tmp-", renderTrafficConfig(serialized, "database-rebuild"), true); err != nil {
		return err
	}
	log.Printf("Rebuilt Traefik traffic config with %d routes at %s", len(serialized), a.Cfg.TraefikConfigPath)
	return nil
}
