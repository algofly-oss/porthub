package connections

import (
	"context"
	"sort"
	"strconv"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// userConnection mirrors _get_user_connection (404 when missing).
func (h *handlers) userConnection(ctx context.Context, user core.Doc, dataID string) (core.Doc, error) {
	id, err := core.ParseOID(dataID, "Invalid connection id")
	if err != nil {
		return nil, err
	}
	connection, err := h.app.FindOne(ctx, "connections", bson.M{"_id": id, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, httpapi.Fail(404, "Connection not found")
	}
	return connection, nil
}

func (h *handlers) requireFirewall() error {
	if !h.app.FirewallConfigured() {
		return httpapi.Fail(503, "Firewall integration is not configured")
	}
	return nil
}

func policyReply(msg string, connection, machine core.Doc, public bool, ips []any, applied bool, app *core.App) *out {
	return reply(msg, map[string]any{
		"connection": app.SerializeConnection(connection, machine),
		"firewall":   map[string]any{"is_public": public, "allowed_ips": ips, "applied": applied},
	})
}

func (h *handlers) getFirewallPolicy(ctx context.Context, in *dataIDPath) (*out, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	connection, err := h.userConnection(ctx, user, in.DataID)
	if err != nil {
		return nil, err
	}
	machine, err := h.machine(ctx, connection)
	if err != nil {
		return nil, err
	}
	policy := core.FirewallPolicy(connection)
	return policyReply("Connection firewall policy fetched successfully", connection, machine,
		policy["is_public"].(bool), policy["allowed_ips"].([]any), enabledValue(connection), h.app), nil
}

// enabledValue mirrors bool(connection.get("enabled", True)).
func enabledValue(connection core.Doc) bool {
	_, ok := connection["enabled"]
	return !ok || core.Truthy(connection, "enabled")
}

// setPolicy stores a policy, syncs the firewall and answers like Python.
func (h *handlers) setPolicy(ctx context.Context, connection core.Doc, public bool, ips []string, msg string) (*out, error) {
	allowed := bson.A{}
	for _, ip := range ips {
		allowed = append(allowed, ip)
	}
	policy := bson.D{{Key: "is_public", Value: public}, {Key: "allowed_ips", Value: allowed}}
	if _, err := h.app.C("connections").UpdateOne(ctx, bson.M{"_id": connection["_id"]}, bson.M{"$set": bson.M{"firewall": policy}}); err != nil {
		return nil, err
	}
	connection["firewall"] = policy
	h.app.SyncConnectionFirewall(ctx, connection)
	machine, err := h.machine(ctx, connection)
	if err != nil {
		return nil, err
	}
	applied := enabledValue(connection)
	return policyReply(msg, connection, machine, public, []any(allowed), applied, h.app), nil
}

func (h *handlers) updateFirewallPolicy(ctx context.Context, in *firewallPolicyIn) (*out, error) {
	m, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	data, err := parseFirewallPolicy(m)
	if err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	connection, err := h.userConnection(ctx, user, data.DataID)
	if err != nil {
		return nil, err
	}
	return h.setPolicy(ctx, connection, data.IsPublic, data.AllowedIPs, "Connection firewall policy updated successfully")
}

func (h *handlers) deleteFirewallPolicy(ctx context.Context, in *dataIDPath) (*out, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	connection, err := h.userConnection(ctx, user, in.DataID)
	if err != nil {
		return nil, err
	}
	return h.setPolicy(ctx, connection, true, nil, "Connection firewall policy deleted successfully")
}

// portKey makes Mongo and firewall JSON port numbers comparable (Python 22 == 22.0).
func portKey(v any) any {
	if f, ok := core.Number(v); ok {
		return f
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return v
}

func (h *handlers) activeFirewallPorts(ctx context.Context, _ *struct{}) (*out, error) {
	if err := h.requireFirewall(); err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	connections, err := h.app.FindAll(ctx, "connections", bson.M{"user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	byPort := map[any]core.Doc{}
	for _, c := range connections {
		if c["external_port"] != nil {
			byPort[portKey(c["external_port"])] = c
		}
	}
	machines, err := h.machinesFor(ctx, connections, notNone)
	if err != nil {
		return nil, err
	}
	active, err := h.app.ListActivePorts(ctx)
	if err != nil {
		return nil, httpapi.Fail(502, err.Error())
	}
	filtered := []any{}
	for _, raw := range active {
		item, _ := raw.(map[string]any)
		port := item["port"]
		connection := byPort[portKey(port)]
		if connection == nil {
			continue
		}
		filtered = append(filtered, map[string]any{
			"port":       port,
			"last_seen":  item["last_seen"],
			"connection": h.app.SerializeConnection(connection, machines[connection["machine_id"]]),
		})
	}
	return reply("Connection firewall activity fetched successfully", filtered), nil
}

func (h *handlers) firewallTraffic(ctx context.Context, in *snapshotIn) (*out, error) {
	m, err := pymodel.Load(in.Body)
	if err != nil {
		return nil, err
	}
	dataIDs, err := parseSnapshot(m)
	if err != nil {
		return nil, err
	}
	if err := h.requireFirewall(); err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	query := bson.M{"user_id": user["_id"]}
	if len(dataIDs) > 0 {
		ids := bson.A{}
		for _, dataID := range dataIDs {
			id, err := core.ParseOID(dataID, "Invalid connection id")
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		query["_id"] = bson.M{"$in": ids}
	}
	connections, err := h.app.FindAll(ctx, "connections", query)
	if err != nil {
		return nil, err
	}
	machines, err := h.machinesFor(ctx, connections, notNone)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, c := range connections {
		if port, ok := core.Int(c, "external_port"); ok && !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	snapshot, err := h.app.TrafficSnapshot(ctx, ports)
	if err != nil {
		return nil, httpapi.Fail(502, err.Error())
	}
	data := []any{}
	for _, c := range connections {
		key := core.IDString(c["external_port"])
		if port, ok := core.Int(c, "external_port"); ok {
			key = strconv.Itoa(port)
		}
		traffic := snapshot[key]
		if !pymodel.Truthy(traffic) {
			traffic = []any{}
		}
		data = append(data, map[string]any{
			"connection": h.app.SerializeConnection(c, machines[c["machine_id"]]),
			"traffic":    traffic,
		})
	}
	return reply("Connection firewall traffic snapshot fetched successfully", data), nil
}

type recentHitsIn struct {
	DataID string `path:"data_id"`
	Limit  string `query:"limit" doc:"integer (default 10)"`
}

func (h *handlers) recentIPHits(ctx context.Context, in *recentHitsIn) (*out, error) {
	limit := 10
	if values, ok := httpapi.Request(ctx).URL.Query()["limit"]; ok && len(values) > 0 {
		n, ok := pymodel.Int(values[len(values)-1])
		if !ok || !n.IsInt64() {
			return nil, pymodel.Fail(pymodel.Item{Loc: []any{"query", "limit"}, Msg: "value is not a valid integer", Type: "type_error.integer"})
		}
		limit = int(n.Int64())
	}
	if err := h.requireFirewall(); err != nil {
		return nil, err
	}
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	connection, err := h.userConnection(ctx, user, in.DataID)
	if err != nil {
		return nil, err
	}
	port, _ := core.Int(connection, "external_port")
	hits, err := h.app.RecentIPHits(ctx, port, limit)
	if err != nil {
		return nil, httpapi.Fail(502, err.Error())
	}
	return reply("Connection recent IP hits fetched successfully", hits), nil
}
