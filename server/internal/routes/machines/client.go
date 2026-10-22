package machines

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Socket.IO events announced to machine clients (shared/sockets.py).
const (
	ctsConfigSnapshot = "/cts/machines/config-snapshot"
	stcConfigSnapshot = "/stc/machines/config-snapshot"
	stcConfigChanged  = "/stc/machines/config-changed"
)

func (h *h) registerClient(api huma.API) {
	G, P := http.MethodGet, http.MethodPost
	huma.Register(api, op("machine-client-auth", P, "/api/machines/client/auth", "Machine Client Auth"), h.clientSession("authenticated"))
	huma.Register(api, op("machine-client-sync", P, "/api/machines/client/sync", "Machine Client Sync"), h.clientSession("synced"))
	huma.Register(api, op("machine-private-install", P, "/api/machines/client/private-install", "Complete Requested Private Enrollment"), h.pendingPrivateInstall)
	huma.Register(api, op("machine-client-deletion-ack", P, "/api/machines/client/deletion-ack", "Machine Client Deletion Ack"), h.deletionAck)
	huma.Register(api, op("machine-client-config", G, "/api/machines/client/config", "Machine Client Config"), h.clientConfig)
	huma.Register(api, op("machine-client-config-toml", G, "/api/machines/client/config.toml", "Machine Client Config Toml"), h.clientConfigTOML)
	huma.Register(api, op("machine-client-changes", G, "/api/machines/client/changes", "Machine Client Changes"), h.clientChanges)
	huma.Register(api, op("machine-client-changes-toml", G, "/api/machines/client/changes.toml", "Machine Client Changes Toml"), h.clientChangesTOML)
	huma.Register(api, op("machine-client-log-stream-status", G, "/api/machines/client/log-stream", "Machine Client Log Stream Status"), h.logStreamStatus)
	huma.Register(api, op("machine-client-logs", P, "/api/machines/client/logs", "Machine Client Logs"), h.clientLogs)
}

// clientControlHeaders mirrors _apply_client_control_headers.
func (h *h) clientControlHeaders(machine core.Doc) []header {
	target := core.Trim(machine, "client_update_target_version")
	requestID := core.Trim(machine, "client_update_request_id")
	requested := "false"
	if requestID != "" && requestID != core.Trim(machine, "client_update_last_handled_request_id") {
		requested = "true"
	}
	out := []header{
		{"X-PortHub-Client-Latest-Version", h.app.ClientVersion()},
		{"X-PortHub-Client-Current-Version", core.Trim(machine, "client_version")},
		{"X-PortHub-Client-Update-Requested", requested},
	}
	if target != "" {
		out = append(out, header{"X-PortHub-Client-Target-Version", target})
	}
	if requestID != "" {
		out = append(out, header{"X-PortHub-Client-Update-Request-Id", requestID})
	}
	return out
}

// --- auth / sync ---

type clientSessionIn struct {
	Body struct {
		_                                struct{} `json:"-" additionalProperties:"true"`
		MachineID                        string   `json:"machine_id" example:"67f7d26b760bd71f4d3f3c34"`
		Token                            string   `json:"token" minLength:"1"`
		Hostname                         *string  `json:"hostname" required:"false" example:"luna.local"`
		LocalIP                          *string  `json:"local_ip" required:"false" example:"192.168.0.3"`
		PublicIP                         *string  `json:"public_ip" required:"false" example:"203.0.113.25"`
		IsActive                         *bool    `json:"is_active" required:"false" example:"true"`
		ClientVersion                    *string  `json:"client_version" required:"false" example:"2f41f3d8a1c4"`
		ClientUpdateLastHandledRequestID *string  `json:"client_update_last_handled_request_id" required:"false" example:"a1b2c3d4e5f6"`
	}
}

// clientSession mirrors _sync_and_build_session.
func (h *h) clientSession(action string) func(context.Context, *clientSessionIn) (*rawOut, error) {
	return func(ctx context.Context, in *clientSessionIn) (*rawOut, error) {
		app, data := h.app, in.Body
		machine, err := app.AuthenticateMachine(ctx, data.MachineID, data.Token)
		if err != nil {
			return nil, err
		}
		r := httpapi.Request(ctx)
		updated, err := app.SyncMachineRuntime(ctx, machine, r, core.SyncInput{
			Hostname: deref(data.Hostname), LocalIP: deref(data.LocalIP), PublicIP: deref(data.PublicIP),
			ClientVersion: deref(data.ClientVersion), HandledRequestID: deref(data.ClientUpdateLastHandledRequestID),
		})
		if err != nil {
			return nil, err
		}
		isOnline := app.IsOnline(updated)
		serialized := app.SerializeMachine(updated)
		id := core.IDString(updated["_id"])
		app.Events.SetCachedStatus(id, isOnline)
		observed, _ := serialized["public_ip"].(string)
		ips, err := h.privateIPs(ctx, updated)
		if err != nil {
			return nil, err
		}
		headers := append([]header{{"X-PortHub-Observed-IP", observed}}, h.clientControlHeaders(updated)...)
		headers = append(headers, header{"X-PortHub-Private-IPs", strings.Join(ips, ", ")})
		// Emit every successful heartbeat so the UI last-seen timestamp stays fresh.
		app.Events.MachineStatusChanged(ctx, updated)
		bundle, err := app.MachineConfigBundle(ctx, updated, r)
		if err != nil {
			return nil, err
		}
		out := map[string]any{
			"msg": "Machine " + action + " successfully",
			"data": map[string]any{
				"machine":   serialized,
				"config":    bundle,
				"endpoints": app.MachineEndpoints(updated, r),
				"socket_auth": map[string]any{
					"machine_id": id,
					"token":      core.JSON(updated["token"]),
					"role":       "machine",
				},
				"socket": map[string]any{
					"path": "/socket.io",
					"events": map[string]any{
						"request_config_snapshot": ctsConfigSnapshot,
						"config_snapshot":         stcConfigSnapshot,
						"config_changed":          stcConfigChanged,
					},
				},
				"polling": map[string]any{"strategy": "long-poll", "changes_query_parameter": "since"},
				"client": map[string]any{
					"current_version":       serialized["client_version"],
					"latest_version":        serialized["latest_client_version"],
					"update_requested":      serialized["client_update_requested"],
					"update_target_version": serialized["client_update_target_version"],
				},
			},
		}
		return raw(200, append([]header{{"Content-Type", "application/json"}}, headers...), jsonBytes(out)), nil
	}
}

// --- deletion ack ---

type deletionAckIn struct {
	Body struct {
		_         struct{} `json:"-" additionalProperties:"true"`
		MachineID string   `json:"machine_id" example:"67f7d26b760bd71f4d3f3c34"`
		Token     string   `json:"token" minLength:"1"`
	}
}

func (h *h) deletionAck(ctx context.Context, in *deletionAckIn) (*anyBody, error) {
	oid, err := core.ParseOID(in.Body.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": oid, "token": in.Body.Token})
	if err != nil {
		return nil, err
	}
	removed := machine != nil && core.Truthy(machine, "deletion_pending")
	if removed {
		if _, err := h.app.C("machines").DeleteOne(ctx, bson.M{"_id": machine["_id"]}); err != nil {
			return nil, err
		}
	}
	return body(map[string]any{
		"msg":  "Machine deletion acknowledged",
		"data": map[string]any{"machine_id": in.Body.MachineID, "removed": removed},
	}), nil
}

// --- config / long-poll changes ---

type credsIn struct {
	MachineID string `query:"machine_id" required:"true"`
	Token     string `query:"token" required:"true" minLength:"1"`
}

type changesIn struct {
	MachineID   string `query:"machine_id" required:"true"`
	Token       string `query:"token" required:"true" minLength:"1"`
	Since       string `query:"since" required:"true" minLength:"1"`
	WaitSeconds int    `query:"wait_seconds" minimum:"1" maximum:"300"`
}

func (h *h) clientConfig(ctx context.Context, in *credsIn) (*anyBody, error) {
	machine, err := h.app.AuthenticateMachine(ctx, in.MachineID, in.Token)
	if err != nil {
		return nil, err
	}
	bundle, err := h.app.MachineConfigBundle(ctx, machine, httpapi.Request(ctx))
	if err != nil {
		return nil, err
	}
	return body(map[string]any{"msg": "Machine config fetched successfully", "data": bundle}), nil
}

func clientTOML(bundle map[string]any) []byte {
	files, _ := bundle["files"].(map[string]any)
	s, _ := files["client.toml"].(string)
	return []byte(s)
}

func (h *h) clientConfigTOML(ctx context.Context, in *credsIn) (*rawOut, error) {
	machine, err := h.app.AuthenticateMachine(ctx, in.MachineID, in.Token)
	if err != nil {
		return nil, err
	}
	bundle, err := h.app.MachineConfigBundle(ctx, machine, httpapi.Request(ctx))
	if err != nil {
		return nil, err
	}
	return raw(200, []header{
		{"Content-Type", textPlain},
		{"Cache-Control", "no-store"},
		{"X-PortHub-Config-Version", bundle["version"].(string)},
		{"X-PortHub-Machine-Id", core.IDString(machine["_id"])},
		{"X-PortHub-Client-Latest-Version", h.app.ClientVersion()},
	}, clientTOML(bundle)), nil
}

// waitForChange runs the long poll; it ends early when the client goes away.
func (h *h) waitForChange(ctx context.Context, in *changesIn) (map[string]any, error) {
	return h.app.WaitForConfigChange(ctx, in.MachineID, in.Token, in.Since, httpapi.Request(ctx), time.Duration(in.WaitSeconds)*time.Second)
}

func (h *h) clientChanges(ctx context.Context, in *changesIn) (*anyBody, error) {
	bundle, err := h.waitForChange(ctx, in)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return body(map[string]any{
			"msg":  "No machine config changes available",
			"data": map[string]any{"changed": false, "version": in.Since},
		}), nil
	}
	return body(map[string]any{
		"msg":  "Machine config changes fetched successfully",
		"data": map[string]any{"changed": true, "config": bundle},
	}), nil
}

func (h *h) clientChangesTOML(ctx context.Context, in *changesIn) (*rawOut, error) {
	bundle, err := h.waitForChange(ctx, in)
	if err != nil {
		return nil, err
	}
	machine, err := h.app.AuthenticateMachine(ctx, in.MachineID, in.Token)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		headers := []header{
			{"Cache-Control", "no-store"},
			{"X-PortHub-Config-Version", in.Since},
			{"X-PortHub-Machine-Id", in.MachineID},
		}
		return raw(http.StatusNoContent, append(headers, h.clientControlHeaders(machine)...), nil), nil
	}
	headers := []header{
		{"Content-Type", textPlain},
		{"Cache-Control", "no-store"},
		{"X-PortHub-Config-Version", bundle["version"].(string)},
		{"X-PortHub-Machine-Id", bundle["machine_id"].(string)},
	}
	return raw(200, append(headers, h.clientControlHeaders(machine)...), clientTOML(bundle)), nil
}

// --- log stream ---

// logClient mirrors the shared start of the log routes: like Python, any
// token of a live machine is accepted; a stale one marks auth required.
func (h *h) logClient(ctx context.Context, machineID, token string) (core.Doc, bool, error) {
	app := h.app
	machine, err := app.AuthenticateMachineForLogs(ctx, machineID)
	if err != nil {
		return nil, false, err
	}
	stored, ok := machine["token"].(string)
	authRequired := !ok || token != stored
	machine, err = app.TouchMachinePresence(ctx, machine, authRequired)
	if err != nil {
		return nil, false, err
	}
	app.Events.SetCachedStatus(core.IDString(machine["_id"]), app.IsOnline(machine))
	app.Events.MachineStatusChanged(ctx, machine)
	stored, ok = machine["token"].(string)
	return machine, !ok || token != stored, nil
}

func (h *h) logStreamStatus(ctx context.Context, in *credsIn) (*rawOut, error) {
	machine, authRequired, err := h.logClient(ctx, in.MachineID, in.Token)
	if err != nil {
		return nil, err
	}
	id := core.IDString(machine["_id"])
	active := h.app.Events.LogStreamRequested(id)
	return raw(200, []header{
		{"Content-Type", "application/json"},
		{"Cache-Control", "no-store"},
		{"X-PortHub-Log-Stream-Active", boolText(active)},
		{"X-PortHub-Machine-Id", id},
		{"X-PortHub-Machine-Auth-Required", boolText(authRequired)},
	}, []byte(`{"active":`+boolText(active)+`}`)), nil
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type clientLogsIn struct {
	Body struct {
		_         struct{} `json:"-" additionalProperties:"true"`
		MachineID string   `json:"machine_id" example:"67f7d26b760bd71f4d3f3c34"`
		Token     string   `json:"token" minLength:"1"`
		Source    *string  `json:"source" required:"false" example:"client"`
		Lines     []string `json:"lines" required:"false"`
	}
}

func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// cleanLogLines mirrors the line filter of machine_client_logs.
func cleanLogLines(lines []string) []string {
	if len(lines) > 100 {
		lines = lines[:100]
	}
	out := []string{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, truncateRunes(strings.TrimRight(line, "\r\n"), 4000))
	}
	return out
}

func (h *h) clientLogs(ctx context.Context, in *clientLogsIn) (*anyBody, error) {
	machine, _, err := h.logClient(ctx, in.Body.MachineID, in.Body.Token)
	if err != nil {
		return nil, err
	}
	lines := cleanLogLines(in.Body.Lines)
	if len(lines) > 0 {
		source := deref(in.Body.Source)
		if source == "" {
			source = "client"
		}
		h.app.Events.LogLines(ctx, machine, lines, truncateRunes(source, 32))
	}
	return body(map[string]any{
		"msg":  "Machine logs received successfully",
		"data": map[string]any{"machine_id": core.IDString(machine["_id"]), "count": len(lines)},
	}), nil
}

// pendingPrivateInstall completes automatic private enrollment while retaining
// ownership revocations and workspace membership checks.
func (h *h) pendingPrivateInstall(ctx context.Context, in *clientSessionIn) (*rawOut, error) {
	machine, err := h.app.AuthenticateMachine(ctx, in.Body.MachineID, in.Body.Token)
	if err != nil {
		return nil, err
	}
	if core.Truthy(machine, "private_owner_revoked") {
		return raw(204, nil, nil), nil
	}
	if err := h.ensurePrivateEnrollment(ctx, machine); err != nil {
		return nil, err
	}
	peers, err := h.app.FindAll(ctx, "private_peers", bson.M{"machine_id": machine["_id"], "owner_id": machine["user_id"], "enabled": true, "credential_hash": bson.M{"$exists": false}}, options.Find().SetLimit(2))
	if err != nil {
		return nil, err
	}
	if len(peers) == 0 {
		return raw(204, nil, nil), nil
	}
	if len(peers) != 1 {
		return nil, httpapi.Fail(409, "Choose which pending private workspace to install")
	}
	peer := peers[0]
	if peer["workspace_id"] != machine["user_id"] {
		membership, err := h.app.FindOne(ctx, "workspace_members", bson.M{"_id": core.IDString(peer["workspace_id"]) + ":" + core.IDString(machine["user_id"])})
		if err != nil {
			return nil, err
		}
		role := core.Str(membership, "role")
		if role != "admin" && role != "member" {
			return nil, httpapi.Fail(403, "Machine owner no longer belongs to the private workspace")
		}
	}
	now := core.Now()
	ticket := core.RandomString(43)
	if _, err = h.app.C("private_install_tickets").UpdateMany(ctx, bson.M{"peer_id": peer["_id"], "consumed_at": nil}, bson.M{"$set": bson.M{"consumed_at": now}}); err != nil {
		return nil, err
	}
	if _, err = h.app.C("private_install_tickets").InsertOne(ctx, bson.M{"_id": core.TokenDigest(ticket), "peer_id": peer["_id"], "created_by": machine["user_id"], "consumed_at": nil, "expires_at": now.Add(10 * time.Minute)}); err != nil {
		return nil, err
	}
	content, err := h.privateInstaller(httpapi.Request(ctx), ticket)
	if err != nil {
		return nil, err
	}
	return raw(200, []header{{"Content-Type", textPlain}, {"Cache-Control", "no-store"}}, []byte(content)), nil
}
