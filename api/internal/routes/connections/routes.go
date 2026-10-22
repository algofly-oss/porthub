// Package connections ports api/router/connections and
// api/shared/connection_refresh.py.
package connections

import (
	"context"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/validation"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type handlers struct{ app *core.App }

type out struct{ Body map[string]any }

func reply(msg string, data any) *out {
	return &out{Body: map[string]any{"msg": msg, "data": data}}
}

type connectionIn struct{ Body *connectionBody }
type dataIDIn struct{ Body *dataIDBody }
type firewallPolicyIn struct{ Body *firewallPolicyBody }
type snapshotIn struct{ Body *snapshotBody }
type dataIDPath struct {
	DataID string `path:"data_id"`
}

func Register(api huma.API, app *core.App) {
	h := &handlers{app}
	tags := []string{"Connections"}
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: "/api/connections" + path, Summary: summary, Tags: tags, SkipValidateBody: true}
	}
	huma.Register(api, op("add-connection", http.MethodPost, "/add", "Add Connection"), h.add)
	huma.Register(api, op("get-connection-firewall-policy", http.MethodGet, "/firewall/policy/{data_id}", "Get Connection Firewall Policy"), h.getFirewallPolicy)
	huma.Register(api, op("update-connection-firewall-policy", http.MethodPut, "/firewall/policy", "Update Connection Firewall Policy"), h.updateFirewallPolicy)
	huma.Register(api, op("delete-connection-firewall-policy", http.MethodDelete, "/firewall/policy/{data_id}", "Delete Connection Firewall Policy"), h.deleteFirewallPolicy)
	huma.Register(api, op("get-user-active-firewall-ports", http.MethodGet, "/firewall/active", "Get User Active Firewall Ports"), h.activeFirewallPorts)
	huma.Register(api, op("get-connection-firewall-traffic", http.MethodPost, "/firewall/traffic/snapshot", "Get Connection Firewall Traffic"), h.firewallTraffic)
	huma.Register(api, op("get-connection-recent-ip-hits", http.MethodGet, "/firewall/recent-ip-hits/{data_id}", "Get Connection Recent Ip Hits"), h.recentIPHits)
	huma.Register(api, op("update-connection", http.MethodPut, "/update", "Update Connection"), h.update)
	huma.Register(api, op("list-connections", http.MethodGet, "/list", "List Connections"), h.list)
	huma.Register(api, op("get-random-port", http.MethodGet, "/random", "Get Random Port"), h.randomPort)
	huma.Register(api, op("external-port-availability", http.MethodGet, "/external-port/{port}/availability", "External Port Availability"), h.portAvailability)
	huma.Register(api, op("delete-connection", http.MethodPost, "/delete", "Delete Connection"), h.delete)
	huma.Register(api, op("connection-command", http.MethodGet, "/command/{_id}", "Connection Command"), h.command)
	huma.Register(api, op("refresh-connection", http.MethodPost, "/refresh", "Refresh Connection"), h.refresh)
}

func (h *handlers) machine(ctx context.Context, connection core.Doc) (core.Doc, error) {
	if !core.Truthy(connection, "machine_id") {
		return nil, nil
	}
	return h.app.FindOne(ctx, "machines", bson.M{"_id": connection["machine_id"]})
}

func (h *handlers) emitConfigChanged(ctx context.Context, machineID any) {
	if h.app.Events != nil {
		h.app.Events.MachineConfigChanged(ctx, core.IDString(machineID))
	}
}

func (h *handlers) add(ctx context.Context, in *connectionIn) (*out, error) {
	m, err := validation.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseConnection(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	serviceName := validation.Strip(data.ServiceName)
	if serviceName == "" {
		return nil, httpapi.Fail(400, "Service name is required")
	}
	machineID, err := core.ParseOID(data.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": machineID, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(400, "Machine not found")
	}
	if !h.app.Cfg.PortAllowed(data.ExternalPort) {
		return nil, httpapi.Fail(400, h.app.Cfg.PortRangeError())
	}
	existing, err := h.app.FindOne(ctx, "connections", bson.M{"external_port": data.ExternalPort})
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, httpapi.Fail(400, "Port already in use")
	}

	now := core.Now()
	autoRefresh := data.AutoRefreshEnabled != nil && *data.AutoRefreshEnabled
	var interval, nextAt any
	if autoRefresh {
		minutes := 60
		if data.AutoRefreshIntervalMinutes != nil && *data.AutoRefreshIntervalMinutes != 0 {
			minutes = *data.AutoRefreshIntervalMinutes
		}
		interval, nextAt = minutes, now.Add(time.Duration(minutes)*time.Minute)
	}
	result, err := h.app.C("connections").InsertOne(ctx, bson.D{
		{Key: "user_id", Value: user["_id"]},
		{Key: "machine_id", Value: machine["_id"]},
		{Key: "service_name", Value: serviceName},
		{Key: "service_description", Value: validation.Strip(deref(data.ServiceDescription))},
		{Key: "internal_ip", Value: data.InternalIP},
		{Key: "internal_port", Value: data.InternalPort},
		{Key: "external_port", Value: data.ExternalPort},
		{Key: "enabled", Value: data.Enabled == nil || *data.Enabled},
		{Key: "auto_refresh_enabled", Value: autoRefresh},
		{Key: "auto_refresh_interval_minutes", Value: interval},
		{Key: "auto_refresh_next_at", Value: nextAt},
		{Key: "firewall", Value: bson.D{{Key: "is_public", Value: true}, {Key: "allowed_ips", Value: bson.A{}}}},
		{Key: "created_at", Value: now},
		{Key: "updated_at", Value: now},
	})
	if err != nil {
		return nil, err
	}
	res, err := h.app.FindOne(ctx, "connections", bson.M{"_id": result.InsertedID})
	if err != nil {
		return nil, err
	}
	h.app.SyncConnectionFirewall(ctx, res)
	if err := h.app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	h.emitConfigChanged(ctx, machine["_id"])
	return reply("Connection added successfully", h.app.SerializeConnection(res, machine)), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (h *handlers) update(ctx context.Context, in *connectionIn) (*out, error) {
	m, err := validation.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseConnection(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	serviceName := validation.Strip(data.ServiceName)
	if serviceName == "" {
		return nil, httpapi.Fail(400, "Service name is required")
	}
	machineID, err := core.ParseOID(data.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": machineID, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(400, "Machine not found")
	}
	connectionID, err := core.ParseOID(deref(data.DataID), "Invalid connection id")
	if err != nil {
		return nil, err
	}
	connection, err := h.app.FindOne(ctx, "connections", bson.M{"_id": connectionID, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, httpapi.Fail(400, "Connection not found")
	}
	if !h.app.Cfg.PortAllowed(data.ExternalPort) {
		return nil, httpapi.Fail(400, h.app.Cfg.PortRangeError())
	}
	existing, err := h.app.FindOne(ctx, "connections", bson.M{"external_port": data.ExternalPort, "_id": bson.M{"$ne": connection["_id"]}})
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, httpapi.Fail(400, "Port already in use")
	}

	now := core.Now()
	autoRefresh := data.AutoRefreshEnabled != nil && *data.AutoRefreshEnabled
	var interval any
	minutes := 0
	if autoRefresh {
		minutes = 60
		if data.AutoRefreshIntervalMinutes != nil && *data.AutoRefreshIntervalMinutes != 0 {
			minutes = *data.AutoRefreshIntervalMinutes
		}
		interval = minutes
	}
	nextEnabled := data.Enabled == nil || *data.Enabled
	existingInterval, hasInterval := core.Number(connection["auto_refresh_interval_minutes"])
	resetSchedule := autoRefresh && (!core.Truthy(connection, "auto_refresh_enabled") ||
		!hasInterval || existingInterval != float64(minutes) ||
		!core.Truthy(connection, "auto_refresh_next_at") ||
		(core.IsFalse(connection, "enabled") && nextEnabled))
	fields := bson.D{
		{Key: "machine_id", Value: machine["_id"]},
		{Key: "service_name", Value: serviceName},
		{Key: "service_description", Value: validation.Strip(deref(data.ServiceDescription))},
		{Key: "internal_ip", Value: data.InternalIP},
		{Key: "internal_port", Value: data.InternalPort},
		{Key: "external_port", Value: data.ExternalPort},
		{Key: "enabled", Value: nextEnabled},
		{Key: "auto_refresh_enabled", Value: autoRefresh},
		{Key: "auto_refresh_interval_minutes", Value: interval},
		{Key: "updated_at", Value: now},
	}
	if resetSchedule && minutes != 0 {
		fields = append(fields, bson.E{Key: "auto_refresh_next_at", Value: now.Add(time.Duration(minutes) * time.Minute)})
	} else if !autoRefresh {
		fields = append(fields, bson.E{Key: "auto_refresh_next_at", Value: nil})
	}
	if _, err := h.app.C("connections").UpdateOne(ctx, bson.M{"_id": connection["_id"]}, bson.M{"$set": fields}); err != nil {
		return nil, err
	}
	if err := h.app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	h.emitConfigChanged(ctx, machine["_id"])
	if previous := connection["machine_id"]; core.Truthy(connection, "machine_id") && previous != machine["_id"] {
		h.emitConfigChanged(ctx, previous)
	}
	if previous, ok := core.Int(connection, "external_port"); ok && previous != 0 && previous != data.ExternalPort {
		h.app.DeletePortPolicyBestEffort(ctx, previous)
	}
	res, err := h.app.FindOne(ctx, "connections", bson.M{"_id": connection["_id"]})
	if err != nil {
		return nil, err
	}
	h.app.SyncConnectionFirewall(ctx, res)
	return reply("Connection updated successfully", h.app.SerializeConnection(res, machine)), nil
}

func (h *handlers) list(ctx context.Context, _ *struct{}) (*out, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	connections, err := h.app.FindAll(ctx, "connections", bson.M{"user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	machines, err := h.machinesFor(ctx, connections, core.Truthy)
	if err != nil {
		return nil, err
	}
	data := []any{}
	for _, c := range connections {
		data = append(data, h.app.SerializeConnection(c, machines[c["machine_id"]]))
	}
	return reply("Connections listed successfully", data), nil
}

// machinesFor loads the machines of connections whose machine_id passes keep.
func (h *handlers) machinesFor(ctx context.Context, connections []core.Doc, keep func(core.Doc, string) bool) (map[any]core.Doc, error) {
	ids := bson.A{}
	seen := map[any]bool{}
	for _, c := range connections {
		if id := c["machine_id"]; keep(c, "machine_id") && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	machines, err := h.app.FindAll(ctx, "machines", bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}
	byID := map[any]core.Doc{}
	for _, m := range machines {
		byID[m["_id"]] = m
	}
	return byID, nil
}

func notNone(d core.Doc, key string) bool { return d[key] != nil }

type portOut struct {
	Body struct {
		Port int `json:"port"`
	}
}

func (h *handlers) randomPort(ctx context.Context, _ *struct{}) (*portOut, error) {
	out := &portOut{}
	cfg := h.app.Cfg
	if cfg.PortRangeStart == 0 {
		for {
			port := 10000 + rand.IntN(65535-10000+1)
			used, err := h.app.FindOne(ctx, "connections", bson.M{"external_port": port})
			if err != nil {
				return nil, err
			}
			if used == nil {
				out.Body.Port = port
				return out, nil
			}
		}
	}
	values, err := h.app.C("connections").Distinct(ctx, "external_port",
		bson.M{"external_port": bson.M{"$gte": cfg.PortRangeStart, "$lte": cfg.PortRangeEnd}}).Raw()
	if err != nil {
		return nil, err
	}
	used := map[int]bool{}
	if arr, err := values.Values(); err == nil {
		for _, v := range arr {
			if n, ok := v.AsInt64OK(); ok {
				used[int(n)] = true
			} else if f, ok := v.DoubleOK(); ok && f == float64(int(f)) {
				used[int(f)] = true
			}
		}
	}
	available := []int{}
	for port := cfg.PortRangeStart; port <= cfg.PortRangeEnd; port++ {
		if !used[port] {
			available = append(available, port)
		}
	}
	if len(available) == 0 {
		return nil, httpapi.Fail(409, "No available external ports in the configured range")
	}
	out.Body.Port = available[rand.IntN(len(available))]
	return out, nil
}

type availabilityIn struct {
	Port   string `path:"port" doc:"integer"`
	DataID string `query:"data_id"`
}

type availabilityOut struct {
	Body struct {
		Available bool    `json:"available"`
		Message   *string `json:"message"`
	}
}

func (h *handlers) portAvailability(ctx context.Context, in *availabilityIn) (*availabilityOut, error) {
	n, ok := validation.Int(in.Port)
	if !ok {
		return nil, validation.Fail(validation.Item{Loc: []any{"path", "port"}, Msg: "value is not a valid integer", Type: "type_error.integer"})
	}
	if _, err := h.app.User(ctx); err != nil {
		return nil, err
	}
	if !n.IsInt64() || n.Int64() < 1 || n.Int64() > 65535 {
		return nil, httpapi.Fail(400, "Invalid port")
	}
	port := int(n.Int64())
	out := &availabilityOut{}
	if !h.app.Cfg.PortAllowed(port) {
		msg := h.app.Cfg.PortRangeError()
		out.Body.Message = &msg
		return out, nil
	}
	query := bson.M{"external_port": port}
	if in.DataID != "" {
		id, err := core.ParseOID(in.DataID, "Invalid connection id")
		if err != nil {
			return nil, err
		}
		query["_id"] = bson.M{"$ne": id}
	}
	connection, err := h.app.FindOne(ctx, "connections", query)
	if err != nil {
		return nil, err
	}
	out.Body.Available = connection == nil
	if connection != nil {
		msg := "External port is already assigned"
		out.Body.Message = &msg
	}
	return out, nil
}

func (h *handlers) delete(ctx context.Context, in *dataIDIn) (*out, error) {
	m, err := validation.Load(in.Body)
	if err != nil {
		return nil, err
	}
	dataID, err := parseDataID(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	id, err := core.ParseOID(dataID, "Invalid connection id")
	if err != nil {
		return nil, err
	}
	connection, err := h.app.FindOne(ctx, "connections", bson.M{"_id": id, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, httpapi.Fail(400, "Connection not found")
	}
	machine, err := h.machine(ctx, connection)
	if err != nil {
		return nil, err
	}
	if _, err := h.app.C("connections").DeleteOne(ctx, bson.M{"_id": connection["_id"]}); err != nil {
		return nil, err
	}
	if err := h.app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	if port, ok := core.Int(connection, "external_port"); ok && port != 0 {
		h.app.DeletePortPolicyBestEffort(ctx, port)
	}
	if machine != nil {
		h.emitConfigChanged(ctx, machine["_id"])
	}
	return reply("Connection deleted successfully", h.app.SerializeConnection(connection, machine)), nil
}

type commandIn struct {
	ID string `path:"_id"`
}

func (h *handlers) command(ctx context.Context, _ *commandIn) (*struct{}, error) {
	return nil, httpapi.Fail(410, "Per-connection client scripts are deprecated. Use the machine bootstrap endpoint instead.")
}

func (h *handlers) refresh(ctx context.Context, in *dataIDIn) (*out, error) {
	m, err := validation.Load(in.Body)
	if err != nil {
		return nil, err
	}
	dataID, err := parseDataID(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	id, err := core.ParseOID(dataID, "Invalid connection id")
	if err != nil {
		return nil, err
	}
	connection, err := h.app.FindOne(ctx, "connections", bson.M{"_id": id, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, httpapi.Fail(400, "Connection not found")
	}
	if core.IsFalse(connection, "enabled") {
		return nil, httpapi.Fail(400, "Enable the service before refreshing")
	}
	// Like the Python handler, finish the refresh even if the client leaves.
	refreshed, err := RefreshConnection(context.WithoutCancel(ctx), h.app, connection, true)
	if err != nil {
		return nil, err
	}
	if refreshed == nil {
		return nil, httpapi.Fail(400, "Could not refresh connection")
	}
	machine, err := h.machine(ctx, refreshed)
	if err != nil {
		return nil, err
	}
	return reply("Connection refreshed successfully", h.app.SerializeConnection(refreshed, machine)), nil
}
