package access

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/routes/access/policy"
	"github.com/algofly-oss/porthub/server/internal/routes/pymodel"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func (h *handlers) workspaces(ctx context.Context, _ string, _ any) (*output, error) {
	user, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	ms, err := h.app.FindAll(ctx, "workspace_members", bson.M{"user_id": user["_id"]})
	if err != nil {
		return nil, err
	}
	ids := []any{user["_id"]}
	roles := map[string]string{}
	for _, m := range ms {
		ids = append(ids, m["workspace_id"])
		roles[core.IDString(m["workspace_id"])] = core.Str(m, "role")
	}
	roles[core.IDString(user["_id"])] = "owner"
	owners, err := h.app.FindAll(ctx, "users", bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, o := range owners {
		name := core.Str(o, "name")
		if name == "" {
			name = core.Str(o, "username")
		}
		out = append(out, map[string]any{"id": core.IDString(o["_id"]), "name": name + "'s Workspace", "role": roles[core.IDString(o["_id"])]})
	}
	return data(out), nil
}
func (h *handlers) snapshot(ctx context.Context, _ string, _ any) (*output, error) {
	_, owner, role, err := h.browser(ctx, false)
	if err != nil {
		return nil, err
	}
	machines, err := h.app.FindAll(ctx, "machines", bson.M{"user_id": owner, "deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return nil, err
	}
	groups, err := h.app.FindAll(ctx, "machine_groups", bson.M{"user_id": owner}, options.Find().SetSort(core.Sort("sort_order", 1, "name", 1)))
	if err != nil {
		return nil, err
	}
	ids, ms, err := h.members(ctx, owner)
	if err != nil {
		return nil, err
	}
	users, err := h.app.FindAll(ctx, "users", bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}
	roles := map[string]string{owner.Hex(): "owner"}
	for _, m := range ms {
		roles[core.IDString(m["user_id"])] = core.Str(m, "role")
	}
	books, err := h.app.FindAll(ctx, "access_rulebooks", bson.M{"user_id": owner}, options.Find().SetSort(core.Sort("created_at", 1)))
	if err != nil {
		return nil, err
	}
	prefs, err := h.preferences(ctx, owner)
	if err != nil {
		return nil, err
	}
	names, peers, err := h.workspaceNames(ctx, owner)
	if err != nil {
		return nil, err
	}
	labels, aliases := privateNames(names, peers)
	machineNames := map[string]any{}
	for _, m := range names {
		machineNames[core.IDString(m["_id"])] = core.Get(m, "name", "")
	}
	machineOut := []any{}
	for _, m := range machines {
		gids := []string{}
		for _, id := range core.MachineGroupIDs(m) {
			gids = append(gids, id.Hex())
		}
		po := m["private_owner_id"]
		if !core.Truthy(m, "private_owner_id") {
			po = owner
		}
		machineOut = append(machineOut, map[string]any{"_id": core.IDString(m["_id"]), "name": core.Get(m, "name", ""), "group_ids": gids, "private_owner_id": core.IDString(po), "private_owner_revoked": core.Truthy(m, "private_owner_revoked"), "enabled": core.Get(m, "enabled", true), "connection_status": h.app.ConnectionStatus(m)})
	}
	userOut := []any{}
	for _, u := range users {
		userOut = append(userOut, map[string]any{"_id": core.IDString(u["_id"]), "name": core.Get(u, "name", ""), "email": core.Get(u, "username", ""), "role": roles[core.IDString(u["_id"])]})
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id.Hex()] = true
	}
	groupOut := []any{}
	for _, g := range groups {
		uids := []string{}
		for _, id := range core.List(g, "user_ids") {
			s := core.IDString(id)
			if allowed[s] {
				uids = append(uids, s)
			}
		}
		groupOut = append(groupOut, map[string]any{"_id": core.IDString(g["_id"]), "name": core.Get(g, "name", ""), "user_ids": uids})
	}
	sort.SliceStable(peers, func(i, j int) bool {
		return labels[core.IDString(peers[i]["_id"])] < labels[core.IDString(peers[j]["_id"])]
	})
	peerOut := []any{}
	now := core.Now()
	for _, p := range peers {
		id := core.IDString(p["_id"])
		last, ok := core.AsTime(p["last_seen_at"])
		paths := []string{}
		seen := map[string]bool{}
		if pm, ok := core.Map(p, "paths"); ok {
			for _, v := range pm {
				s := fmt.Sprint(v)
				if !seen[s] {
					paths = append(paths, s)
					seen[s] = true
				}
			}
		}
		sort.Strings(paths)
		aa := aliases[id]
		if aa == nil {
			aa = []string{}
		}
		peerOut = append(peerOut, map[string]any{"_id": id, "machine_id": core.IDString(p["machine_id"]), "machine_name": machineNames[core.IDString(p["machine_id"])], "ip": p["ip"], "hostname": labels[id], "custom_hostname": core.Truthy(p, "hostname"), "aliases": aa, "enabled": core.Get(p, "enabled", true), "installed": core.Truthy(p, "credential_hash"), "online": ok && now.Sub(last) < 30*time.Second, "last_seen_at": core.JSON(p["last_seen_at"]), "paths": paths})
	}
	invites := []core.Doc{}
	if role == "owner" || role == "admin" {
		invites, err = h.app.FindAll(ctx, "workspace_invites", bson.M{"user_id": owner, "consumed_at": nil, "revoked_at": nil, "expires_at": bson.M{"$gt": core.Now()}}, options.Find().SetProjection(bson.M{"email": 1, "role": 1, "expires_at": 1}))
		if err != nil {
			return nil, err
		}
	}
	return reply(map[string]any{"workspace_id": owner.Hex(), "role": role, "transport_ready": false, "network": prefs.Dict(), "machines": machineOut, "users": userOut, "groups": groupOut, "books": core.JSON(books), "private_peers": peerOut, "invitations": core.JSON(invites)}), nil
}
func (h *handlers) validateSelectors(ctx context.Context, b policy.RuleBook, owner bson.ObjectID) error {
	groups := map[string]bool{b.GroupID: true}
	machines := map[string]bool{}
	users := map[string]bool{}
	for _, r := range b.Rules {
		for _, ss := range [][]policy.Selector{r.Sources, r.Destinations} {
			for _, s := range ss {
				switch s.Kind {
				case "group":
					groups[s.ID] = true
				case "machine":
					machines[s.ID] = true
				case "user":
					users[s.ID] = true
				}
			}
		}
	}
	for _, item := range []struct {
		kind, coll string
		ids        map[string]bool
	}{{"group", "machine_groups", groups}, {"machine", "machines", machines}} {
		ids := []bson.ObjectID{}
		seen := map[bson.ObjectID]bool{}
		for s := range item.ids {
			id, err := core.ParseOID(s, "Invalid "+item.kind+" identifier")
			if err != nil {
				return err
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			n, err := h.app.C(item.coll).CountDocuments(ctx, bson.M{"user_id": owner, "_id": bson.M{"$in": ids}})
			if err != nil {
				return err
			}
			if n != int64(len(ids)) {
				return httpapi.Fail(400, "Every selected "+item.kind+" must belong to this workspace")
			}
		}
	}
	ids, _, err := h.members(ctx, owner)
	if err != nil {
		return err
	}
	for _, id := range ids {
		delete(users, id.Hex())
	}
	if len(users) > 0 {
		return httpapi.Fail(400, "Selected users must belong to this workspace")
	}
	return nil
}
func (h *handlers) createBook(ctx context.Context, _ string, raw any) (*output, error) {
	b, err := policy.ParseRuleBook(raw)
	if err != nil {
		return nil, err
	}
	u, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	if err = h.validateSelectors(ctx, b, o); err != nil {
		return nil, err
	}
	n, err := h.app.C("access_rulebooks").CountDocuments(ctx, bson.M{"user_id": o})
	if err != nil {
		return nil, err
	}
	if n >= 100 {
		return nil, httpapi.Fail(400, "A workspace can have up to 100 rule books")
	}
	d := b.Dict(true)
	d["revision"] = 1
	d["user_id"] = o
	d["created_by"] = u["_id"]
	d["created_at"] = core.Now()
	d["updated_at"] = d["created_at"]
	r, err := h.app.C("access_rulebooks").InsertOne(ctx, d)
	if err != nil {
		return nil, err
	}
	d["_id"] = r.InsertedID
	return data(core.JSON(d)), nil
}
func (h *handlers) updateBook(ctx context.Context, id string, raw any) (*output, error) {
	b, err := policy.ParseRuleBook(raw)
	if err != nil {
		return nil, err
	}
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	if err = h.validateSelectors(ctx, b, o); err != nil {
		return nil, err
	}
	oid, err := core.ParseOID(id, "Invalid rule book")
	if err != nil {
		return nil, err
	}
	set := b.Dict(false)
	set["updated_at"] = core.Now()
	var d core.Doc
	err = h.app.C("access_rulebooks").FindOneAndUpdate(ctx, bson.M{"_id": oid, "user_id": o, "revision": b.Revision}, bson.M{"$set": set, "$inc": bson.M{"revision": 1}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&d)
	if isMissing(err) {
		return nil, httpapi.Fail(409, "Rule book changed or no longer exists. Reload before saving.")
	}
	if err != nil {
		return nil, err
	}
	return data(core.JSON(d)), nil
}
func (h *handlers) deleteBook(ctx context.Context, id string, raw any) (*output, error) {
	b, err := policy.ParseDeleteBook(raw)
	if err != nil {
		return nil, err
	}
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	oid, err := core.ParseOID(id, "Invalid rule book")
	if err != nil {
		return nil, err
	}
	r, err := h.app.C("access_rulebooks").DeleteOne(ctx, bson.M{"_id": oid, "user_id": o, "revision": b.Revision})
	if err != nil {
		return nil, err
	}
	if r.DeletedCount != 1 {
		return nil, httpapi.Fail(409, "Rule book changed or no longer exists. Reload before deleting.")
	}
	return message("Rule book deleted"), nil
}
func (h *handlers) network(ctx context.Context, _ string, raw any) (*output, error) {
	p, err := policy.ParseNetworkPreferences(raw)
	if err != nil {
		return nil, err
	}
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	set := p.Dict()
	set["updated_at"] = core.Now()
	_, err = h.app.C("private_networks").UpdateOne(ctx, bson.M{"_id": o.Hex()}, bson.M{"$set": set}, options.UpdateOne().SetUpsert(true))
	return reply(map[string]any{"data": p.Dict(), "transport_ready": false}), err
}
func (h *handlers) createGroup(ctx context.Context, _ string, raw any) (*output, error) {
	d, ok := policy.AsDict(raw)
	if !ok {
		return nil, pymodel.Fail(pymodel.Item{Loc: []any{"body"}, Msg: "value is not a valid dict", Type: "type_error.dict"})
	}
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	v, ok := d["name"]
	if !ok {
		v = ""
	}
	name := policy.PyStrip(policy.PyStr(v))
	if name == "" || len([]rune(name)) > 80 {
		return nil, httpapi.Fail(400, "Group name must contain 1–80 characters")
	}
	n, err := h.app.C("machine_groups").CountDocuments(ctx, bson.M{"user_id": o, "name": name})
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, httpapi.Fail(409, "A group with that name already exists")
	}
	r, err := h.app.C("machine_groups").InsertOne(ctx, bson.M{"user_id": o, "name": name, "user_ids": bson.A{}, "sort_order": 0, "created_at": core.Now()})
	if err != nil {
		return nil, err
	}
	return data(map[string]any{"_id": core.IDString(r.InsertedID), "name": name, "user_ids": []any{}}), nil
}
func uniqueIDs(values []string, detail string) ([]bson.ObjectID, error) {
	out := []bson.ObjectID{}
	seen := map[bson.ObjectID]bool{}
	for _, s := range values {
		id, err := core.ParseOID(s, detail)
		if err != nil {
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}
func (h *handlers) groupMembers(ctx context.Context, id string, raw any) (*output, error) {
	b, err := policy.ParseGroupMembers(raw)
	if err != nil {
		return nil, err
	}
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	gid, err := core.ParseOID(id, "Invalid group")
	if err != nil {
		return nil, err
	}
	g, err := h.app.FindOne(ctx, "machine_groups", bson.M{"_id": gid, "user_id": o})
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, httpapi.Fail(404, "Group not found")
	}
	mids, err := uniqueIDs(b.MachineIDs, "Invalid machine")
	if err != nil {
		return nil, err
	}
	uids, err := uniqueIDs(b.UserIDs, "Invalid user")
	if err != nil {
		return nil, err
	}
	if len(mids) > 0 {
		n, err := h.app.C("machines").CountDocuments(ctx, bson.M{"_id": bson.M{"$in": mids}, "user_id": o})
		if err != nil {
			return nil, err
		}
		if n != int64(len(mids)) {
			return nil, httpapi.Fail(400, "Selected machines must belong to this workspace")
		}
	}
	ids, _, err := h.members(ctx, o)
	if err != nil {
		return nil, err
	}
	allowed := map[bson.ObjectID]bool{}
	for _, i := range ids {
		allowed[i] = true
	}
	for _, i := range uids {
		if !allowed[i] {
			return nil, httpapi.Fail(400, "Selected users must belong to this workspace")
		}
	}
	all, err := h.app.FindAll(ctx, "machines", bson.M{"user_id": o})
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if core.Truthy(m, "group_id") && !core.Truthy(m, "group_ids") {
			_, err = h.app.C("machines").UpdateOne(ctx, bson.M{"_id": m["_id"], "user_id": o, "group_ids": m["group_ids"]}, bson.M{"$set": bson.M{"group_ids": core.MachineGroupIDs(m)}, "$unset": bson.M{"group_id": ""}})
			if err != nil {
				return nil, err
			}
		}
	}
	if len(mids) > 0 {
		_, err = h.app.C("machines").UpdateMany(ctx, bson.M{"user_id": o, "_id": bson.M{"$in": mids}}, bson.M{"$addToSet": bson.M{"group_ids": gid}})
		if err != nil {
			return nil, err
		}
	}
	_, err = h.app.C("machines").UpdateMany(ctx, bson.M{"user_id": o, "_id": bson.M{"$nin": mids}}, bson.M{"$pull": bson.M{"group_ids": bson.M{"$in": bson.A{gid, gid.Hex()}}}})
	if err != nil {
		return nil, err
	}
	_, err = h.app.C("machine_groups").UpdateOne(ctx, bson.M{"_id": gid, "user_id": o}, bson.M{"$set": bson.M{"user_ids": uids, "updated_at": core.Now()}})
	return message("Group members saved"), err
}
func (h *handlers) connectionTest(ctx context.Context, _ string, raw any) (*output, error) {
	b, err := policy.ParseConnectionTest(raw)
	if err != nil {
		return nil, err
	}
	_, o, _, err := h.browser(ctx, false)
	if err != nil {
		return nil, err
	}
	src, err := core.ParseOID(b.SourceID, "Invalid source")
	if err != nil {
		return nil, err
	}
	dst, err := core.ParseOID(b.DestinationID, "Invalid destination")
	if err != nil {
		return nil, err
	}
	ms, err := h.app.FindAll(ctx, "machines", bson.M{"user_id": o, "_id": bson.M{"$in": bson.A{src, dst}}})
	if err != nil {
		return nil, err
	}
	by := groupMap(ms)
	if by[b.SourceID] == nil || by[b.DestinationID] == nil {
		return nil, httpapi.Fail(404, "Select two machines in this workspace")
	}
	books, err := h.app.FindAll(ctx, "access_rulebooks", bson.M{"user_id": o})
	if err != nil {
		return nil, err
	}
	gs, err := h.app.FindAll(ctx, "machine_groups", bson.M{"user_id": o})
	if err != nil {
		return nil, err
	}
	return reply(map[string]any{"data": policy.EvaluateAccess(by[b.SourceID], by[b.DestinationID], b.Protocol, b.Port, docs(books), groupMap(gs)), "enforcement": "policy-preview", "transport_ready": false}), nil
}
