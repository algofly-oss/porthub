// Package machines ports api/router/machines: machine management for the
// web app, the machine client API used by installed clients, install
// scripts and client binary downloads.
package machines

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/danielgtaylor/huma/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type h struct{ app *core.App }

type anyBody struct{ Body map[string]any }

func body(m map[string]any) *anyBody { return &anyBody{Body: m} }

func op(id, method, path, summary string) huma.Operation {
	return huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Tags: []string{"Machines"}}
}

// Register adds every /api/machines route.
func Register(api huma.API, app *core.App) {
	h := &h{app: app}
	G, P, U := http.MethodGet, http.MethodPost, http.MethodPut
	// Same order as router/machines/__init__.py.
	huma.Register(api, op("add-machine", P, "/api/machines/add", "Add Machine"), h.add)
	huma.Register(api, op("update-machine", U, "/api/machines/update", "Update Machine"), h.update)
	huma.Register(api, op("add-machine-to-group", P, "/api/machines/groups/add", "Add Machine To Group"), h.addToGroup)
	huma.Register(api, op("remove-machine-from-group", P, "/api/machines/groups/remove", "Remove Machine From Group"), h.removeFromGroup)
	huma.Register(api, op("machine-private-addresses", G, "/api/machines/private-addresses/{machine_id}", "Machine Private Addresses"), h.privateAddresses)
	huma.Register(api, op("list-machines", G, "/api/machines/list", "List Machines"), h.list)
	huma.Register(api, op("delete-machine", P, "/api/machines/delete", "Delete Machine"), h.delete)
	huma.Register(api, op("refresh-machine-token", P, "/api/machines/refresh-token", "Refresh Machine Token"), h.refreshToken)
	huma.Register(api, op("request-machine-client-update", P, "/api/machines/request-client-update", "Request Machine Client Update"), h.requestClientUpdate)
	huma.Register(api, op("sync-machine", P, "/api/machines/sync", "Sync Machine"), h.legacySync)
	pair := newPairAPI(api)
	huma.Register(pair, op("get-machine-status-history", G, statusHistoryPath, "Get Machine Status History"), h.statusHistory)
	huma.Register(pair, op("machine-command", G, commandPath, "Machine Command"), h.command)
	pair.mount()
	h.registerScripts(api)
	h.registerClient(api)
}

// present reports which top-level keys a JSON body sets (pydantic exclude_unset).
func present(raw []byte) map[string]bool {
	keys := map[string]json.RawMessage{}
	_ = json.Unmarshal(raw, &keys)
	out := map[string]bool{}
	for k := range keys {
		out[k] = true
	}
	return out
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// --- add / update ---

// machineBody is models.machine.Machine.
type machineBody struct {
	_                               struct{} `json:"-" additionalProperties:"true"`
	DataID                          *string  `json:"data_id" required:"false"`
	Name                            string   `json:"name" minLength:"1" example:"luna"`
	Hostname                        *string  `json:"hostname" required:"false" example:"luna.local"`
	Enabled                         *bool    `json:"enabled" required:"false" example:"true"`
	IsActive                        *bool    `json:"is_active" required:"false" example:"false"`
	ClientSetupPublicBaseURL        *string  `json:"client_setup_public_base_url" required:"false" example:"https://porthub.example.com"`
	ClientSetupRatholeServerAddress *string  `json:"client_setup_rathole_server_address" required:"false" example:"rathole.example.com:2334"`
	ClientSetupServiceDomain        *string  `json:"client_setup_service_domain" required:"false" example:"services.example.com"`
	GroupIDs                        []string `json:"group_ids" required:"false" example:"[\"67f7d26b760bd71f4d3f3c34\"]"`
	TelegramAlertsExcluded          *bool    `json:"telegram_alerts_excluded" required:"false" example:"false"`
}

type machineIn struct {
	Body    machineBody
	RawBody []byte
}

// validGroups mirrors the group_ids validation of add/update.
func (h *h) validGroups(ctx context.Context, user core.Doc, raw []string) (bson.A, error) {
	out := bson.A{}
	seen := map[bson.ObjectID]bool{}
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		oid, err := core.ParseOID(strings.TrimSpace(item), "Invalid group id")
		if err != nil {
			return nil, err
		}
		group, err := h.app.FindOne(ctx, "machine_groups", bson.M{"_id": oid, "user_id": user["_id"]})
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, httpapi.Fail(400, "Group not found")
		}
		if !seen[oid] {
			seen[oid] = true
			out = append(out, oid)
		}
	}
	return out, nil
}

func aliasList(aliases []string) bson.A {
	out := bson.A{}
	for _, a := range aliases {
		out = append(out, a)
	}
	return out
}

func (h *h) add(ctx context.Context, in *machineIn) (*anyBody, error) {
	app, data := h.app, in.Body
	user, err := app.User(ctx)
	if err != nil {
		return nil, err
	}
	now := core.Now()
	name, aliases, err := core.SplitMachineNames(data.Name)
	if err != nil {
		return nil, err
	}
	groups, err := h.validGroups(ctx, user, data.GroupIDs)
	if err != nil {
		return nil, err
	}
	token, err := app.GenerateMachineToken(ctx)
	if err != nil {
		return nil, err
	}
	enabled := true
	if data.Enabled != nil {
		enabled = *data.Enabled
	}
	hostname := strings.TrimSpace(deref(data.Hostname))
	machine := bson.D{
		{Key: "user_id", Value: user["_id"]},
		{Key: "name", Value: name},
		{Key: "aliases", Value: aliasList(aliases)},
		{Key: "hostname", Value: hostname},
		{Key: "hostname_override", Value: hostname},
		{Key: "client_setup_public_base_url", Value: strings.TrimSpace(deref(data.ClientSetupPublicBaseURL))},
		{Key: "client_setup_rathole_server_address", Value: strings.TrimSpace(deref(data.ClientSetupRatholeServerAddress))},
		{Key: "client_setup_service_domain", Value: strings.TrimSpace(deref(data.ClientSetupServiceDomain))},
		{Key: "client_hostname", Value: ""},
		{Key: "enabled", Value: enabled},
		{Key: "local_ip", Value: ""},
		{Key: "public_ip", Value: ""},
		{Key: "token", Value: token},
		{Key: "log_tokens", Value: bson.A{}},
		{Key: "auth_required", Value: false},
		{Key: "client_version", Value: ""},
		{Key: "client_update_target_version", Value: ""},
		{Key: "client_update_request_id", Value: ""},
		{Key: "client_update_last_handled_request_id", Value: ""},
		{Key: "client_update_requested_at", Value: nil},
		{Key: "client_updated_at", Value: nil},
		{Key: "last_seen_at", Value: nil},
		{Key: "created_at", Value: now},
		{Key: "updated_at", Value: now},
	}
	if len(groups) > 0 {
		machine = append(machine, bson.E{Key: "group_ids", Value: groups})
	}
	res, err := app.C("machines").InsertOne(ctx, machine)
	if err != nil {
		return nil, err
	}
	created, err := app.FindOne(ctx, "machines", bson.M{"_id": res.InsertedID})
	if err != nil {
		return nil, err
	}
	if err := h.ensurePrivateEnrollment(ctx, created); err != nil {
		_, _ = app.C("machines").DeleteOne(ctx, bson.M{"_id": created["_id"]})
		return nil, err
	}
	if err := app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	return body(map[string]any{"msg": "Machine added successfully", "data": app.SerializeMachine(created)}), nil
}

// cleanOptionalText mirrors _clean_optional_text.
func cleanOptionalText(value *string, label string, max int) (string, error) {
	cleaned := strings.TrimSpace(deref(value))
	if len([]rune(cleaned)) > max {
		return "", httpapi.Fail(400, fmt.Sprintf("%s must be %d characters or fewer", label, max))
	}
	return cleaned, nil
}

// urlSplit returns urllib.parse.urlsplit's scheme and netloc.
func urlSplit(raw string) (scheme, netloc string) {
	raw = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(strings.TrimLeft(raw, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f "))
	if i := strings.Index(raw, ":"); i > 0 && isASCIILetter(raw[0]) {
		ok := true
		for _, c := range []byte(raw[:i]) {
			if !isASCIILetter(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
				ok = false
				break
			}
		}
		if ok {
			scheme, raw = strings.ToLower(raw[:i]), raw[i+1:]
		}
	}
	if strings.HasPrefix(raw, "//") {
		rest := raw[2:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		netloc = rest
	}
	return scheme, netloc
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// cleanPublicBaseURL mirrors _clean_public_base_url.
func cleanPublicBaseURL(value *string) (string, error) {
	cleaned, err := cleanOptionalText(value, "PortHub public base URL", 512)
	if err != nil || cleaned == "" {
		return cleaned, err
	}
	scheme, netloc := urlSplit(cleaned)
	if (scheme != "http" && scheme != "https") || netloc == "" {
		return "", httpapi.Fail(400, "PortHub public base URL must be an http(s) URL")
	}
	return strings.TrimRight(cleaned, "/"), nil
}

// sortedGroups mirrors _sorted_group_id_tuple.
func sortedGroups(serialized map[string]any) []string {
	out := []string{}
	ids, _ := serialized["group_ids"].([]any)
	for _, id := range ids {
		if s, ok := id.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func changed(a, b map[string]any, key string) bool { return !reflect.DeepEqual(a[key], b[key]) }

func (h *h) update(ctx context.Context, in *machineIn) (*anyBody, error) {
	app, data := h.app, in.Body
	user, err := app.User(ctx)
	if err != nil {
		return nil, err
	}
	machineID, err := core.ParseOID(deref(data.DataID), "Invalid machine id")
	if err != nil {
		return nil, err
	}
	name, aliases, err := core.SplitMachineNames(data.Name)
	if err != nil {
		return nil, err
	}
	machine, err := app.FindOne(ctx, "machines", bson.M{"_id": machineID, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(400, "Machine not found")
	}
	previous := app.SerializeMachine(machine)
	previousHostname := core.ResolveMachineHostname(machine)
	wasOnline := app.IsOnline(machine)
	var nextEnabled any
	switch {
	case data.Enabled != nil:
		nextEnabled = *data.Enabled
	case data.IsActive != nil:
		nextEnabled = *data.IsActive
	default:
		nextEnabled = core.Get(machine, "enabled", true)
	}
	incoming := present(in.RawBody)
	override := strings.TrimSpace(deref(data.Hostname))
	effective := override
	if effective == "" {
		effective = core.Trim(machine, "client_hostname")
	}
	if effective == "" {
		effective = core.Trim(machine, "hostname")
	}
	set := bson.D{
		{Key: "name", Value: name},
		{Key: "aliases", Value: aliasList(aliases)},
		{Key: "hostname", Value: effective},
		{Key: "hostname_override", Value: override},
		{Key: "enabled", Value: nextEnabled},
		{Key: "updated_at", Value: core.Now()},
	}
	unset := bson.D{}
	if incoming["group_ids"] {
		groups, err := h.validGroups(ctx, user, data.GroupIDs)
		if err != nil {
			return nil, err
		}
		set = append(set, bson.E{Key: "group_ids", Value: groups})
		unset = append(unset, bson.E{Key: "group_id", Value: ""})
	}
	if incoming["client_setup_public_base_url"] {
		v, err := cleanPublicBaseURL(data.ClientSetupPublicBaseURL)
		if err != nil {
			return nil, err
		}
		set = append(set, bson.E{Key: "client_setup_public_base_url", Value: v})
	}
	if incoming["client_setup_rathole_server_address"] {
		v, err := cleanOptionalText(data.ClientSetupRatholeServerAddress, "Rathole server address", 255)
		if err != nil {
			return nil, err
		}
		set = append(set, bson.E{Key: "client_setup_rathole_server_address", Value: v})
	}
	if incoming["client_setup_service_domain"] {
		v, err := cleanOptionalText(data.ClientSetupServiceDomain, "Service domain", 255)
		if err != nil {
			return nil, err
		}
		set = append(set, bson.E{Key: "client_setup_service_domain", Value: v})
	}
	if data.TelegramAlertsExcluded != nil {
		set = append(set, bson.E{Key: "telegram_alerts_excluded", Value: *data.TelegramAlertsExcluded})
	}
	update := bson.D{{Key: "$set", Value: set}}
	if len(unset) > 0 {
		update = append(update, bson.E{Key: "$unset", Value: unset})
	}
	if _, err := app.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, update); err != nil {
		return nil, err
	}
	updated, err := app.FindOne(ctx, "machines", bson.M{"_id": machine["_id"]})
	if err != nil {
		return nil, err
	}
	serialized := app.SerializeMachine(updated)
	updatedHostname := core.ResolveMachineHostname(updated)
	isOnline := app.IsOnline(updated)
	id := core.IDString(updated["_id"])
	app.Events.SetCachedStatus(id, isOnline)

	enabledChanged := changed(previous, serialized, "enabled")
	nameChanged := changed(previous, serialized, "name")
	ratholeChanged := nameChanged || previousHostname != updatedHostname || enabledChanged ||
		changed(previous, serialized, "client_setup_rathole_server_address")
	groupChanged := !reflect.DeepEqual(sortedGroups(previous), sortedGroups(serialized))
	if wasOnline != isOnline || nameChanged || previousHostname != updatedHostname || enabledChanged || groupChanged {
		app.Events.MachineStatusChanged(ctx, updated)
	}
	if ratholeChanged {
		if err := app.RebuildServerTOML(ctx, true); err != nil {
			return nil, err
		}
		app.Events.MachineConfigChanged(ctx, id)
	}
	if enabledChanged {
		if err := app.SyncMachineFirewall(ctx, updated["_id"]); err != nil {
			return nil, err
		}
	}
	return body(map[string]any{"msg": "Machine updated successfully", "data": serialized}), nil
}

// --- group membership ---

type groupMemberIn struct {
	Body struct {
		_         struct{} `json:"-" additionalProperties:"true"`
		MachineID string   `json:"machine_id"`
		GroupID   string   `json:"group_id"`
	}
}

func (h *h) groupMember(ctx context.Context, in *groupMemberIn) (core.Doc, bson.ObjectID, bson.ObjectID, error) {
	var none bson.ObjectID
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, none, none, err
	}
	machineOID, err := core.ParseOID(in.Body.MachineID, "Invalid machine id")
	if err != nil {
		return nil, none, none, err
	}
	groupOID, err := core.ParseOID(in.Body.GroupID, "Invalid group id")
	if err != nil {
		return nil, none, none, err
	}
	machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": machineOID, "user_id": user["_id"]})
	if err != nil {
		return nil, none, none, err
	}
	if machine == nil {
		return nil, none, none, httpapi.Fail(400, "Machine not found")
	}
	group, err := h.app.FindOne(ctx, "machine_groups", bson.M{"_id": groupOID, "user_id": user["_id"]})
	if err != nil {
		return nil, none, none, err
	}
	if group == nil {
		return nil, none, none, httpapi.Fail(400, "Group not found")
	}
	return machine, machineOID, groupOID, nil
}

func oidList(ids []bson.ObjectID) bson.A {
	out := bson.A{}
	for _, id := range ids {
		out = append(out, id)
	}
	return out
}

func (h *h) membershipChanged(ctx context.Context, machineOID bson.ObjectID, msg string) (*anyBody, error) {
	updated, err := h.app.FindOne(ctx, "machines", bson.M{"_id": machineOID})
	if err != nil {
		return nil, err
	}
	h.app.Events.SetCachedStatus(core.IDString(updated["_id"]), h.app.IsOnline(updated))
	h.app.Events.MachineStatusChanged(ctx, updated)
	return body(map[string]any{"msg": msg, "data": h.app.SerializeMachine(updated)}), nil
}

func (h *h) addToGroup(ctx context.Context, in *groupMemberIn) (*anyBody, error) {
	machine, machineOID, groupOID, err := h.groupMember(ctx, in)
	if err != nil {
		return nil, err
	}
	current := core.MachineGroupIDs(machine)
	for _, id := range current {
		if id == groupOID {
			updated, err := h.app.FindOne(ctx, "machines", bson.M{"_id": machineOID})
			if err != nil {
				return nil, err
			}
			return body(map[string]any{"msg": "Machine is already in this group", "data": h.app.SerializeMachine(updated)}), nil
		}
	}
	ids := oidList(append(current, groupOID))
	if _, err := h.app.C("machines").UpdateOne(ctx, bson.M{"_id": machineOID},
		bson.D{{Key: "$set", Value: bson.D{{Key: "group_ids", Value: ids}, {Key: "updated_at", Value: core.Now()}}}, {Key: "$unset", Value: bson.M{"group_id": ""}}}); err != nil {
		return nil, err
	}
	return h.membershipChanged(ctx, machineOID, "Machine added to group successfully")
}

func (h *h) removeFromGroup(ctx context.Context, in *groupMemberIn) (*anyBody, error) {
	machine, machineOID, groupOID, err := h.groupMember(ctx, in)
	if err != nil {
		return nil, err
	}
	current := core.MachineGroupIDs(machine)
	now := core.Now()
	member := false
	rest := []bson.ObjectID{}
	for _, id := range current {
		if id == groupOID {
			member = true
		} else {
			rest = append(rest, id)
		}
	}
	legacy, _ := machine["group_id"].(bson.ObjectID)
	var update bson.D
	switch {
	case member:
		update = bson.D{{Key: "$set", Value: bson.D{{Key: "group_ids", Value: oidList(rest)}, {Key: "updated_at", Value: now}}}, {Key: "$unset", Value: bson.M{"group_id": ""}}}
	case machine["group_id"] != nil && legacy == groupOID:
		update = bson.D{{Key: "$unset", Value: bson.M{"group_id": ""}}, {Key: "$set", Value: bson.M{"updated_at": now}}}
	default:
		return nil, httpapi.Fail(400, "Machine is not in this group")
	}
	if _, err := h.app.C("machines").UpdateOne(ctx, bson.M{"_id": machineOID}, update); err != nil {
		return nil, err
	}
	return h.membershipChanged(ctx, machineOID, "Machine removed from group successfully")
}

// --- list / delete / token / client update ---

func (h *h) list(ctx context.Context, _ *struct{}) (*anyBody, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	machines, err := h.app.FindAll(ctx, "machines", bson.M{"user_id": user["_id"], "deletion_pending": bson.M{"$ne": true}},
		options.Find().SetSort(core.Sort("created_at", 1)))
	if err != nil {
		return nil, err
	}
	peers, err := h.app.FindAll(ctx, "private_peers", bson.M{"owner_id": user["_id"], "enabled": true})
	if err != nil {
		return nil, err
	}
	byMachine := map[string][]core.Doc{}
	for _, peer := range peers {
		id := core.IDString(peer["machine_id"])
		byMachine[id] = append(byMachine[id], peer)
	}
	data := []any{}
	for _, m := range machines {
		serialized := h.app.SerializeMachine(m)
		ips := []string{}
		if !core.Truthy(m, "private_owner_revoked") {
			ips = privatePeerIPs(byMachine[core.IDString(m["_id"])])
		}
		serialized["private_ips"] = ips
		data = append(data, serialized)
	}
	return body(map[string]any{"msg": "Machines listed successfully", "data": data}), nil
}

type dataIDIn struct {
	Body struct {
		_      struct{} `json:"-" additionalProperties:"true"`
		DataID string   `json:"data_id"`
	}
}

func (h *h) ownedMachine(ctx context.Context, dataID string) (core.Doc, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	oid, err := core.ParseOID(dataID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := h.app.FindOne(ctx, "machines", bson.M{"_id": oid, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(400, "Machine not found")
	}
	return machine, nil
}

func (h *h) delete(ctx context.Context, in *dataIDIn) (*anyBody, error) {
	app := h.app
	machine, err := h.ownedMachine(ctx, in.Body.DataID)
	if err != nil {
		return nil, err
	}
	now := core.Now()
	if err := app.DeleteMachineFirewall(ctx, machine["_id"]); err != nil {
		return nil, err
	}
	if _, err := app.C("connections").DeleteMany(ctx, bson.M{"machine_id": machine["_id"]}); err != nil {
		return nil, err
	}
	if _, err := app.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "deletion_pending", Value: true},
			{Key: "deleted_at", Value: now},
			{Key: "enabled", Value: false},
			{Key: "auth_required", Value: false},
			{Key: "last_seen_at", Value: nil},
			{Key: "updated_at", Value: now},
		}},
		{Key: "$unset", Value: bson.D{
			{Key: "log_tokens", Value: ""},
			{Key: "client_setup_public_base_url", Value: ""},
			{Key: "client_setup_rathole_server_address", Value: ""},
			{Key: "client_setup_service_domain", Value: ""},
		}},
	}); err != nil {
		return nil, err
	}
	if err := app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	app.Events.DisconnectMachine(core.IDString(machine["_id"]))
	return body(map[string]any{"msg": "Machine deleted successfully", "data": app.SerializeMachine(machine)}), nil
}

// nextLogTokens mirrors refresh_token's log token rotation: the old token
// first, unique truthy values, at most 5.
func nextLogTokens(current any, previous []any) bson.A {
	out := bson.A{}
	seen := map[string]bool{}
	for _, t := range append([]any{current}, previous...) {
		s, ok := t.(string)
		if !ok || s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == 5 {
			break
		}
	}
	return out
}

func (h *h) refreshToken(ctx context.Context, in *dataIDIn) (*anyBody, error) {
	app := h.app
	machine, err := h.ownedMachine(ctx, in.Body.DataID)
	if err != nil {
		return nil, err
	}
	token, err := app.GenerateMachineToken(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := app.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, bson.M{"$set": bson.D{
		{Key: "token", Value: token},
		{Key: "log_tokens", Value: nextLogTokens(machine["token"], core.List(machine, "log_tokens"))},
		{Key: "updated_at", Value: core.Now()},
	}}); err != nil {
		return nil, err
	}
	updated, err := app.FindOne(ctx, "machines", bson.M{"_id": machine["_id"]})
	if err != nil {
		return nil, err
	}
	if err := app.RebuildServerTOML(ctx, true); err != nil {
		return nil, err
	}
	app.Events.DisconnectMachine(core.IDString(updated["_id"]))
	return body(map[string]any{"msg": "Machine token refreshed successfully", "data": app.SerializeMachine(updated)}), nil
}

func tokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *h) requestClientUpdate(ctx context.Context, in *dataIDIn) (*anyBody, error) {
	app := h.app
	machine, err := h.ownedMachine(ctx, in.Body.DataID)
	if err != nil {
		return nil, err
	}
	now := core.Now()
	if _, err := app.C("machines").UpdateOne(ctx, bson.M{"_id": machine["_id"]}, bson.M{"$set": bson.D{
		{Key: "client_update_target_version", Value: app.ClientVersion()},
		{Key: "client_update_request_id", Value: tokenHex(8)},
		{Key: "client_update_requested_at", Value: now},
		{Key: "updated_at", Value: now},
	}}); err != nil {
		return nil, err
	}
	updated, err := app.FindOne(ctx, "machines", bson.M{"_id": machine["_id"]})
	if err != nil {
		return nil, err
	}
	app.Events.MachineStatusChanged(ctx, updated)
	return body(map[string]any{"msg": "Machine client update requested successfully", "data": app.SerializeMachine(updated)}), nil
}

// --- status history ---

type statusHistoryIn struct {
	MachineID string `path:"machine_id"`
	Days      int    `query:"days" default:"365" minimum:"1" maximum:"366"`
}

func (h *h) statusHistory(ctx context.Context, in *statusHistoryIn) (*anyBody, error) {
	app := h.app
	user, err := app.User(ctx)
	if err != nil {
		return nil, err
	}
	oid, err := core.ParseOID(in.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := app.FindOne(ctx, "machines", bson.M{"_id": oid, "user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return body(map[string]any{"msg": "Machine not found", "data": []any{}}), nil
	}
	since := time.Now().UTC().Add(-time.Duration(in.Days) * 24 * time.Hour)
	events, err := app.FindAll(ctx, "machine_status_events", bson.M{"machine_id": oid, "changed_at": bson.M{"$gte": since}},
		options.Find().SetSort(core.Sort("changed_at", 1)))
	if err != nil {
		return nil, err
	}
	// The last change before the window tells us the state the window opens in.
	previous, err := app.FindOne(ctx, "machine_status_events", bson.M{"machine_id": oid, "changed_at": bson.M{"$lt": since}},
		options.FindOne().SetSort(core.Sort("changed_at", -1)))
	if err != nil {
		return nil, err
	}
	data := []any{}
	if previous != nil {
		data = append(data, map[string]any{"status": core.JSON(previous["status"]), "changed_at": core.JSON(since)})
	}
	for _, e := range events {
		data = append(data, map[string]any{"status": core.JSON(e["status"]), "changed_at": core.JSON(e["changed_at"])})
	}
	status := "offline"
	if app.IsOnline(machine) {
		status = "online"
	}
	return body(map[string]any{"msg": "Machine status history loaded successfully", "data": data, "current_status": status}), nil
}

// --- legacy sync (/machines/sync) ---

type legacySyncIn struct {
	Body struct {
		_         struct{} `json:"-" additionalProperties:"true"`
		MachineID string   `json:"machine_id" example:"67f7d26b760bd71f4d3f3c34"`
		Token     string   `json:"token" minLength:"1"`
		Hostname  *string  `json:"hostname" required:"false" example:"luna.local"`
		LocalIP   *string  `json:"local_ip" required:"false" example:"192.168.0.3"`
		PublicIP  *string  `json:"public_ip" required:"false" example:"203.0.113.25"`
		IsActive  *bool    `json:"is_active" required:"false" example:"true"`
	}
}

type legacySyncOut struct {
	ObservedIP string `header:"X-PortHub-Observed-IP"`
	Body       map[string]any
}

func (h *h) legacySync(ctx context.Context, in *legacySyncIn) (*legacySyncOut, error) {
	app, data := h.app, in.Body
	oid, err := core.ParseOID(data.MachineID, "Invalid machine id")
	if err != nil {
		return nil, err
	}
	machine, err := app.FindOne(ctx, "machines", bson.M{"_id": oid, "token": data.Token})
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, httpapi.Fail(401, "Invalid machine credentials")
	}
	r := httpapi.Request(ctx)
	updated, err := app.SyncMachineRuntime(ctx, machine, r, core.SyncInput{
		Hostname: deref(data.Hostname), LocalIP: deref(data.LocalIP), PublicIP: deref(data.PublicIP),
	})
	if err != nil {
		return nil, err
	}
	isOnline := app.IsOnline(updated)
	serialized := app.SerializeMachine(updated)
	app.Events.SetCachedStatus(core.IDString(updated["_id"]), isOnline)
	app.Events.MachineStatusChanged(ctx, updated)
	bundle, err := app.MachineConfigBundle(ctx, updated, r)
	if err != nil {
		return nil, err
	}
	observed, _ := serialized["public_ip"].(string)
	return &legacySyncOut{ObservedIP: observed, Body: map[string]any{
		"msg":       "Machine synced successfully",
		"data":      serialized,
		"config":    bundle,
		"endpoints": app.MachineEndpoints(updated, r),
	}}, nil
}
