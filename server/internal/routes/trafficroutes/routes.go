// Package trafficroutes ports api/router/traffic_routes and
// api/shared/proxy_activity.py.
package trafficroutes

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type handlers struct{ app *core.App }

type out struct{ Body map[string]any }

func reply(msg string, data any) *out {
	return &out{Body: map[string]any{"msg": msg, "data": data}}
}

type routeIn struct{ Body *routeBody }
type deleteIn struct{ Body *deleteBody }

func Register(api huma.API, app *core.App) {
	h := &handlers{app}
	tags := []string{"Traffic Routes"}
	op := func(id, method, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: "/api/traffic-routes" + path, Summary: summary, Tags: tags, SkipValidateBody: true}
	}
	huma.Register(api, op("add-traffic-route", http.MethodPost, "/add", "Add Traffic Route"), h.add)
	huma.Register(api, op("update-traffic-route", http.MethodPut, "/update", "Update Traffic Route"), h.update)
	huma.Register(api, op("list-traffic-routes", http.MethodGet, "/list", "List Traffic Routes"), h.list)
	huma.Register(api, op("delete-traffic-route", http.MethodPost, "/delete", "Delete Traffic Route"), h.delete)
	huma.Register(api, op("proxy-activity", http.MethodGet, "/activity", "Proxy Activity"), h.activity)
}

// conflictingHosts mirrors _find_conflicting_hosts.
func (h *handlers) conflictingHosts(ctx context.Context, hosts []string, exclude any) ([]string, error) {
	query := bson.M{"hosts": bson.M{"$in": hosts}}
	if exclude != nil {
		query["_id"] = bson.M{"$ne": exclude}
	}
	routes, err := h.app.FindAll(ctx, "traffic_routes", query)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, host := range hosts {
		wanted[host] = true
	}
	found := map[string]bool{}
	for _, route := range routes {
		for _, host := range core.List(route, "hosts") {
			if s, ok := host.(string); ok && wanted[s] {
				found[s] = true
			}
		}
	}
	out := make([]string, 0, len(found))
	for host := range found {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}

// connectionMetadata mirrors _resolve_connection_metadata.
func (h *handlers) connectionMetadata(ctx context.Context, userID any, dataID string) (any, error) {
	if dataID == "" {
		return nil, nil
	}
	id, err := core.ParseOID(dataID, "Invalid connection id")
	if err != nil {
		return nil, err
	}
	connection, err := h.app.FindOne(ctx, "connections", bson.M{"_id": id, "user_id": userID})
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, httpapi.Fail(400, "Mapped port-pair entry not found")
	}
	var machine core.Doc
	machineID := connection["machine_id"]
	if core.Truthy(connection, "machine_id") {
		if machine, err = h.app.FindOne(ctx, "machines", bson.M{"_id": machineID}); err != nil {
			return nil, err
		}
	}
	meta := bson.D{
		{Key: "data_id", Value: core.IDString(connection["_id"])},
		{Key: "machine_id", Value: ""},
		{Key: "machine_name", Value: ""},
		{Key: "machine_hostname", Value: ""},
		{Key: "service_name", Value: core.Get(connection, "service_name", "")},
		{Key: "service_description", Value: core.Get(connection, "service_description", "")},
		{Key: "internal_ip", Value: core.InternalIP(connection)},
		{Key: "internal_port", Value: connection["internal_port"]},
		{Key: "external_port", Value: connection["external_port"]},
		{Key: "enabled", Value: core.Get(connection, "enabled", true)},
	}
	if core.Truthy(connection, "machine_id") {
		meta[1].Value = core.IDString(machineID)
	}
	if machine != nil {
		meta[2].Value = core.Get(machine, "name", "")
		meta[3].Value = core.ResolveMachineHostname(machine)
	}
	return meta, nil
}

func hostsMessage(hosts []string) string {
	return "Hosts already in use: " + strings.Join(hosts, ", ")
}

func strArray(items []string) bson.A {
	out := bson.A{}
	for _, s := range items {
		out = append(out, s)
	}
	return out
}

func (h *handlers) add(ctx context.Context, in *routeIn) (*out, error) {
	m, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseRoute(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	name := pymodel.Strip(data.Name)
	if name == "" {
		return nil, httpapi.Fail(400, "Route name is required")
	}
	hosts := data.normalizedHosts()
	conflicts, err := h.conflictingHosts(ctx, hosts, nil)
	if err != nil {
		return nil, err
	}
	if len(conflicts) > 0 {
		return nil, httpapi.Fail(400, hostsMessage(conflicts))
	}
	now := core.Now()
	connection, err := h.connectionMetadata(ctx, user["_id"], pymodel.Strip(deref(data.ConnectionDataID)))
	if err != nil {
		return nil, err
	}
	result, err := h.app.C("traffic_routes").InsertOne(ctx, bson.D{
		{Key: "user_id", Value: user["_id"]},
		{Key: "name", Value: name},
		{Key: "group", Value: pymodel.Strip(data.Group)},
		{Key: "description", Value: pymodel.Strip(deref(data.Description))},
		{Key: "hosts", Value: strArray(hosts)},
		{Key: "target_mode", Value: data.TargetMode},
		{Key: "target_url", Value: data.normalizedTargetURL()},
		{Key: "entry_points", Value: strArray(data.normalizedEntryPoints())},
		{Key: "enabled", Value: data.Enabled == nil || *data.Enabled},
		{Key: "connection", Value: connection},
		{Key: "created_at", Value: now},
		{Key: "updated_at", Value: now},
	})
	if err != nil {
		return nil, err
	}
	created, err := h.app.FindOne(ctx, "traffic_routes", bson.M{"_id": result.InsertedID})
	if err != nil {
		return nil, err
	}
	if err := h.app.RebuildTrafficConfig(ctx); err != nil {
		return nil, err
	}
	return reply("Traffic route created successfully", core.SerializeTrafficRoute(created)), nil
}

func (h *handlers) userRoute(ctx context.Context, user core.Doc, dataID string) (bson.ObjectID, core.Doc, error) {
	id, err := core.ParseOID(dataID, "Invalid traffic route id")
	if err != nil {
		return id, nil, err
	}
	route, err := h.app.FindOne(ctx, "traffic_routes", bson.M{"_id": id, "user_id": user["_id"]})
	if err != nil {
		return id, nil, err
	}
	if route == nil {
		return id, nil, httpapi.Fail(400, "Traffic route not found")
	}
	return id, route, nil
}

func (h *handlers) update(ctx context.Context, in *routeIn) (*out, error) {
	m, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseRoute(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	id, _, err := h.userRoute(ctx, user, deref(data.DataID))
	if err != nil {
		return nil, err
	}
	name := pymodel.Strip(data.Name)
	if name == "" {
		return nil, httpapi.Fail(400, "Route name is required")
	}
	hosts := data.normalizedHosts()
	conflicts, err := h.conflictingHosts(ctx, hosts, id)
	if err != nil {
		return nil, err
	}
	if len(conflicts) > 0 {
		return nil, httpapi.Fail(400, hostsMessage(conflicts))
	}
	connection, err := h.connectionMetadata(ctx, user["_id"], pymodel.Strip(deref(data.ConnectionDataID)))
	if err != nil {
		return nil, err
	}
	if _, err := h.app.C("traffic_routes").UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.D{
		{Key: "name", Value: name},
		{Key: "group", Value: pymodel.Strip(data.Group)},
		{Key: "description", Value: pymodel.Strip(deref(data.Description))},
		{Key: "hosts", Value: strArray(hosts)},
		{Key: "target_mode", Value: data.TargetMode},
		{Key: "target_url", Value: data.normalizedTargetURL()},
		{Key: "entry_points", Value: strArray(data.normalizedEntryPoints())},
		{Key: "enabled", Value: data.Enabled == nil || *data.Enabled},
		{Key: "connection", Value: connection},
		{Key: "updated_at", Value: core.Now()},
	}}); err != nil {
		return nil, err
	}
	updated, err := h.app.FindOne(ctx, "traffic_routes", bson.M{"_id": id})
	if err != nil {
		return nil, err
	}
	if err := h.app.RebuildTrafficConfig(ctx); err != nil {
		return nil, err
	}
	return reply("Traffic route updated successfully", core.SerializeTrafficRoute(updated)), nil
}

func (h *handlers) list(ctx context.Context, _ *struct{}) (*out, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	routes, err := h.app.FindAll(ctx, "traffic_routes", bson.M{"user_id": user["_id"]},
		options.Find().SetSort(core.Sort("created_at", 1, "_id", 1)))
	if err != nil {
		return nil, err
	}
	data := []any{}
	for _, route := range routes {
		data = append(data, core.SerializeTrafficRoute(route))
	}
	return reply("Traffic routes listed successfully", data), nil
}

func (h *handlers) delete(ctx context.Context, in *deleteIn) (*out, error) {
	m, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	dataID, _ := m.ReqStr("data_id")
	if err := m.Err(); err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	id, route, err := h.userRoute(ctx, user, dataID)
	if err != nil {
		return nil, err
	}
	if _, err := h.app.C("traffic_routes").DeleteOne(ctx, bson.M{"_id": id}); err != nil {
		return nil, err
	}
	if err := h.app.RebuildTrafficConfig(ctx); err != nil {
		return nil, err
	}
	return reply("Traffic route deleted successfully", core.SerializeTrafficRoute(route)), nil
}
