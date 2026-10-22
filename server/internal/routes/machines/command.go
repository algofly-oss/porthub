package machines

import (
	"context"
	"crypto/subtle"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var scriptAssetFilenames = map[string]string{
	"install": "install.sh",
	"client":  "porthub-client.sh",
}

// scriptPlaceholders lists the replacements in render_script_asset's order,
// as placeholder -> endpoint key ("" for values that are not endpoints).
var scriptPlaceholders = [][2]string{
	{"__PORT_HUB_CLIENT_VERSION__", ""},
	{"__PORT_HUB_API_URL__", ""},
	{"__PORT_HUB_MACHINE_ID__", ""},
	{"__PORT_HUB_MACHINE_TOKEN__", ""},
	{"__PORT_HUB_AUTH_URL__", "auth"},
	{"__PORT_HUB_SYNC_URL__", "sync"},
	{"__PORT_HUB_CONFIG_TOML_URL__", "config_toml"},
	{"__PORT_HUB_CHANGES_TOML_URL__", "changes_toml"},
	{"__PORT_HUB_LOG_STREAM_STATUS_URL__", "log_stream_status"},
	{"__PORT_HUB_LOG_STREAM_UPLOAD_URL__", "log_stream_upload"},
	{"__PORT_HUB_RATHOLE_X86_64_URL__", "rathole_x86_64"},
	{"__PORT_HUB_RATHOLE_DARWIN_X86_64_URL__", "rathole_darwin_x86_64"},
	{"__PORT_HUB_RATHOLE_DARWIN_ARM64_URL__", "rathole_darwin_arm64"},
	{"__PORT_HUB_RATHOLE_ARM64_URL__", "rathole_arm64"},
	{"__PORT_HUB_RATHOLE_ARMHF_URL__", "rathole_armhf"},
	{"__PORT_HUB_RATHOLE_ARMV7_URL__", "rathole_armv7"},
	{"__PORT_HUB_CLI_URL__", "client_cli"},
}

// renderScript replaces the placeholders in order (fixed values first).
func renderScript(content string, fixed map[string]string, endpoints map[string]string) string {
	for _, p := range scriptPlaceholders {
		value := fixed[p[0]]
		if p[1] != "" {
			value = endpoints[p[1]]
		}
		content = strings.ReplaceAll(content, p[0], value)
	}
	return content
}

// renderScriptAsset mirrors render_script_asset.
func (h *h) renderScriptAsset(name string, r *http.Request, machine core.Doc) (string, error) {
	filename, ok := scriptAssetFilenames[name]
	if !ok {
		return "", httpapi.Fail(404, "Unsupported script asset")
	}
	app := h.app
	endpoints := app.MachineEndpoints(machine, r)
	fixed := map[string]string{
		"__PORT_HUB_CLIENT_VERSION__": app.ClientVersion(),
		"__PORT_HUB_API_URL__":        app.APIBaseURL(r, machine, core.RequestOverrides(r)),
		"__PORT_HUB_MACHINE_ID__":     core.IDString(machine["_id"]),
		"__PORT_HUB_MACHINE_TOKEN__":  core.Str(machine, "token"),
	}
	path := filepath.Join(filepath.Dir(app.ClientScriptPath()), filename)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return "", httpapi.Fail(404, "Asset not found: "+filename)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return renderScript(string(data), fixed, endpoints), nil
}

// installCommand keeps enrollment in the URL, with no local script to manage.
func installCommand(endpoints map[string]string, _ string) string {
	return "curl -fsSL " + shellQuoteURL(endpoints["install_script"]) + " | bash"
}

func shellQuoteURL(s string) string {
	if !strings.ContainsAny(s, "&;|<>$`\\\"' ()\t\r\n") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// clientSetupValues mirrors build_client_setup_values.
func (h *h) clientSetupValues(r *http.Request, machine core.Doc) map[string]any {
	app := h.app
	o := core.RequestOverrides(r)
	defaultBase := app.PublicBaseURL(r)
	overrides := map[string]any{}
	effective := map[string]any{
		"rathole_server_address": app.RatholeServerAddress(r, machine, o),
		"service_domain":         app.SetupServiceDomain(machine, o),
	}
	for _, kv := range [][2]string{
		{"public_base_url", "client_setup_public_base_url"},
		{"rathole_server_address", "client_setup_rathole_server_address"},
		{"service_domain", "client_setup_service_domain"},
	} {
		overrides[kv[0]] = strings.TrimSpace(firstNonEmpty(o[kv[1]], core.Str(machine, kv[1])))
	}
	effective["public_base_url"] = firstNonEmpty(overrides["public_base_url"].(string), defaultBase)
	return map[string]any{
		"defaults": map[string]any{
			"public_base_url":        defaultBase,
			"rathole_server_address": app.RatholeServerAddress(r, nil, nil),
			"service_domain":         strings.TrimSpace(app.Cfg.ServiceDomain),
		},
		"overrides": overrides,
		"effective": effective,
	}
}

type commandIn struct {
	MachineID string `path:"machine_id"`
}

func (h *h) command(ctx context.Context, in *commandIn) (*anyBody, error) {
	app := h.app
	user, err := app.User(ctx)
	if err != nil {
		return nil, err
	}
	oid, err := core.ParseOID(in.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := app.FindOne(ctx, "machines", bson.M{"_id": oid, "user_id": user["_id"], "deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(400, "Machine not found")
	}
	r := httpapi.Request(ctx)
	ticket, err := h.installTicket(ctx, machine, r)
	if err != nil {
		return nil, err
	}

	endpoints := app.MachineEndpoints(machine, r)
	endpoints["install_script"] = app.MachinePublicBaseURL(machine, r, core.RequestOverrides(r)) + "/install/" + ticket
	return body(map[string]any{
		"msg": "Machine command generated successfully",
		"data": map[string]any{
			"machine":      app.SerializeMachine(machine),
			"command":      installCommand(endpoints, core.IDString(machine["_id"])),
			"client_setup": h.clientSetupValues(r, machine),
		},
	}), nil
}

// installTicket keeps one code per machine credential. Preview changes update
// the effective setup behind that code, including changes to the access URL.
func (h *h) installTicket(ctx context.Context, machine core.Doc, r *http.Request) (string, error) {
	app := h.app
	overrides := core.RequestOverrides(r)
	setup := bson.M{"public_base_url": app.MachinePublicBaseURL(machine, r, overrides), "rathole_server_address": app.RatholeServerAddress(r, machine, overrides), "service_domain": app.SetupServiceDomain(machine, overrides)}
	tokenDigest := core.TokenDigest(core.Str(machine, "token"))
	key := "public:" + core.TokenDigest(core.IDString(machine["_id"])+":"+tokenDigest)
	coll := app.C("machine_install_tickets")
	for _, model := range []mongo.IndexModel{
		{Keys: core.Sort("expires_at", 1), Options: options.Index().SetExpireAfterSeconds(0)},
		{Keys: core.Sort("ticket_hash", 1), Options: options.Index().SetUnique(true).SetSparse(true)},
	} {
		if _, err := coll.Indexes().CreateOne(ctx, model); err != nil {
			return "", err
		}
	}
	fresh := func() bson.M {
		code := core.RandomString(16)
		return bson.M{"code": code, "ticket_hash": core.TokenDigest(code), "kind": "public", "machine_id": machine["_id"], "token_digest": tokenDigest, "expires_at": core.Now().Add(24 * time.Hour)}
	}
	var ticket core.Doc
	err := coll.FindOneAndUpdate(ctx, bson.M{"_id": key}, bson.M{"$setOnInsert": fresh(), "$set": bson.M{"setup": setup}}, options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&ticket)
	if mongo.IsDuplicateKeyError(err) {
		err = coll.FindOne(ctx, bson.M{"_id": key}).Decode(&ticket)
	}
	if err != nil {
		return "", err
	}
	if expires, ok := core.AsTime(ticket["expires_at"]); !ok || !expires.After(core.Now()) {
		old := ticket["ticket_hash"]
		err = coll.FindOneAndUpdate(ctx, bson.M{"_id": key, "ticket_hash": old}, bson.M{"$set": fresh()}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&ticket)
		if err == mongo.ErrNoDocuments {
			err = coll.FindOne(ctx, bson.M{"_id": key}).Decode(&ticket)
		}
		if err != nil {
			return "", err
		}
	}
	return core.Str(ticket, "code"), nil
}

func (h *h) privateInstaller(r *http.Request, ticket string) (string, error) {
	source, err := os.ReadFile(filepath.Join(filepath.Dir(h.app.ClientScriptPath()), "private-install.sh"))
	if err != nil {
		return "", err
	}
	literal := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	content := strings.ReplaceAll(string(source), "__PRIVATE_SERVER__", literal(h.app.PublicBaseURL(r)))
	return strings.ReplaceAll(content, "__PRIVATE_TICKET__", literal(ticket)), nil
}

// --- scripts and downloads ---

type machineTokenIn struct {
	MachineID string `path:"machine_id"`
	Token     string `path:"token"`
}

type ratholeIn struct {
	MachineID string `path:"machine_id"`
	Token     string `path:"token"`
	Target    string `path:"target"`
}

func (h *h) registerScripts(api huma.API) {
	G := http.MethodGet
	base := "/api/machines/{machine_id}/{token}"
	script := func(name string, headers ...header) func(context.Context, *machineTokenIn) (*rawOut, error) {
		return func(ctx context.Context, in *machineTokenIn) (*rawOut, error) {
			machine, err := h.app.AuthenticateMachineForLogs(ctx, in.MachineID)
			if err != nil {
				return nil, err
			}
			// The scripts embed the machine token: only its holder may fetch them
			// (the Python API ignored the token in the path).
			if stored, _ := machine["token"].(string); stored == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(in.Token)) != 1 {
				return nil, httpapi.Fail(403, "Invalid machine token")
			}
			content, err := h.renderScriptAsset(name, httpapi.Request(ctx), machine)
			if err != nil {
				return nil, err
			}
			return raw(200, append([]header{{"Content-Type", textPlain}, {"Cache-Control", "no-store"}}, headers...), []byte(content)), nil
		}
	}
	huma.Register(api, op("machine-install-ticket", G, "/install/{ticket}", "Install PortHub"),
		func(ctx context.Context, in *struct {
			Ticket string `path:"ticket"`
		}) (*rawOut, error) {
			if len(in.Ticket) != 16 {
				return nil, httpapi.Fail(403, "Installer link is invalid or expired; refresh the setup page")
			}
			ticket, err := h.app.FindOne(ctx, "machine_install_tickets", bson.M{"$or": bson.A{bson.M{"_id": core.TokenDigest(in.Ticket)}, bson.M{"ticket_hash": core.TokenDigest(in.Ticket)}}, "expires_at": bson.M{"$gt": core.Now()}})
			if err != nil {
				return nil, err
			}
			if ticket == nil {
				return nil, httpapi.Fail(403, "Installer link is invalid or expired; refresh the setup page")
			}
			machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": ticket["machine_id"], "enabled": bson.M{"$ne": false}, "deletion_pending": bson.M{"$ne": true}})
			if err != nil {
				return nil, err
			}
			if machine == nil || core.TokenDigest(core.Str(machine, "token")) != ticket["token_digest"] {
				return nil, httpapi.Fail(403, "Installer link is invalid or expired; refresh the setup page")
			}
			if ticket["kind"] == "private" {
				content, err := h.privateInstaller(httpapi.Request(ctx), core.Str(ticket, "private_ticket"))
				if err != nil {
					return nil, err
				}
				return raw(200, []header{{"Content-Type", textPlain}, {"Cache-Control", "no-store"}, {"Referrer-Policy", "no-referrer"}}, []byte(content)), nil
			}

			request := httpapi.Request(ctx).Clone(ctx)
			if setup, ok := core.Map(ticket, "setup"); ok {
				query := request.URL.Query()
				for key, value := range setup {
					query.Set(key, core.IDString(value))
				}
				request.URL.RawQuery = query.Encode()
			}
			content, err := h.renderScriptAsset("install", request, machine)
			if err != nil {
				return nil, err
			}
			return raw(200, []header{{"Content-Type", textPlain}, {"Cache-Control", "no-store"}, {"Referrer-Policy", "no-referrer"}}, []byte(content)), nil
		})
	// Short, token-authenticated installer URL. Existing URLs stay available.
	huma.Register(api, op("short-machine-install", G, "/api/install/{token}", "Install PortHub"),
		func(ctx context.Context, in *struct {
			Token string `path:"token"`
		}) (*rawOut, error) {
			if len(in.Token) < 32 || len(in.Token) > 200 {
				return nil, httpapi.Fail(403, "Invalid machine token")
			}
			machine, err := h.app.FindOne(ctx, "machines", bson.M{"token": in.Token, "enabled": bson.M{"$ne": false}, "deletion_pending": bson.M{"$ne": true}})
			if err != nil {
				return nil, err
			}
			if machine == nil {
				return nil, httpapi.Fail(403, "Invalid machine token")
			}
			content, err := h.renderScriptAsset("install", httpapi.Request(ctx), machine)
			if err != nil {
				return nil, err
			}
			return raw(200, []header{{"Content-Type", textPlain}, {"Cache-Control", "no-store"}}, []byte(content)), nil
		})
	huma.Register(api, op("machine-install-script", G, base+"/install.sh", "Machine Install Script"), script("install"))
	huma.Register(api, op("machine-client-script", G, base+"/client.sh", "Machine Client Script"), script("client"))
	huma.Register(api, op("machine-cli-download", G, base+"/downloads/porthub", "Machine Cli Download"),
		script("client", header{"Cache-Control", "no-store"}, header{"Content-Disposition", `attachment; filename="porthub"`}))
	huma.Register(api, op("machine-rathole-download", G, base+"/downloads/rathole/{target}", "Machine Rathole Download"), h.ratholeDownload)
}

// ratholeDownload serves the bundled PortHub client binary for the target.
func (h *h) ratholeDownload(ctx context.Context, in *ratholeIn) (*rawOut, error) {
	if _, err := h.app.AuthenticateMachine(ctx, in.MachineID, in.Token); err != nil {
		return nil, err
	}
	target, err := NormalizeTarget(in.Target)
	if err != nil {
		return nil, err
	}
	path, asset, version, err := clientBinary(h.app.Cfg.ClientBinaryDir, target)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, httpapi.Fail(404, "Asset not found: "+asset)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rawOut{Body: func(hctx huma.Context) {
		defer f.Close()
		r, w := humago.Unwrap(hctx)
		for _, hd := range []header{
			{"Content-Type", "application/octet-stream"},
			{"Content-Disposition", `attachment; filename="rathole"`},
			{"Cache-Control", "no-store"},
			{"X-PortHub-Rathole-Target", target},
			{"X-PortHub-Rathole-Release", version},
			{"X-PortHub-Rathole-Asset", asset},
		} {
			w.Header().Set(hd.name, hd.value)
		}
		http.ServeContent(w, r, "", info.ModTime(), f)
	}}, nil
}
