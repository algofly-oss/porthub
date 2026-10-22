package access

import (
	"context"
	"fmt"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/routes/access/policy"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func (h *handlers) workspaceNames(ctx context.Context, o bson.ObjectID) ([]core.Doc, []core.Doc, error) {
	ps, err := h.app.FindAll(ctx, "private_peers", bson.M{"workspace_id": o})
	if err != nil {
		return nil, nil, err
	}
	ids := []any{}
	for _, p := range ps {
		ids = append(ids, p["machine_id"])
	}
	ms, err := h.app.FindAll(ctx, "machines", bson.M{"$or": bson.A{bson.M{"user_id": o}, bson.M{"_id": bson.M{"$in": ids}}}, "deletion_pending": bson.M{"$ne": true}}, options.Find().SetProjection(bson.M{"name": 1, "aliases": 1}))
	return ms, ps, err
}
func (h *handlers) indexes(ctx context.Context) error {
	c := h.app.C("private_peers")
	if _, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: core.Sort("workspace_id", 1, "ip", 1), Options: options.Index().SetUnique(true)}); err != nil {
		return err
	}
	cursor, err := c.Indexes().List(ctx)
	if err != nil {
		return err
	}
	var ix []bson.M
	if err = cursor.All(ctx, &ix); err != nil {
		return err
	}
	for _, i := range ix {
		if i["name"] == "workspace_id_1_alias_1" {
			if err = c.Indexes().DropOne(ctx, "workspace_id_1_alias_1"); err != nil {
				return err
			}
		}
	}
	if _, err = c.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: core.Sort("workspace_id", 1, "hostname", 1), Options: options.Index().SetUnique(true).SetName("workspace_custom_hostname").SetPartialFilterExpression(bson.M{"hostname": bson.M{"$type": "string"}})}); err != nil {
		return err
	}
	for _, name := range []string{"private_install_tickets", "private_signals", "machine_install_tickets"} {
		if _, err = h.app.C(name).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: core.Sort("expires_at", 1), Options: options.Index().SetExpireAfterSeconds(0)}); err != nil {
			return err
		}
	}
	return nil
}
func (h *handlers) hostnameCheck(ctx context.Context, o bson.ObjectID, mid any, name string) error {
	ms, ps, err := h.workspaceNames(ctx, o)
	if err != nil {
		return err
	}
	if clash, ok := policy.HostnameConflict(name, mid, docs(ms), docs(ps)); ok && policy.Truthy(clash) {
		return httpapi.Fail(409, fmt.Sprint(name, " is already used by ", clash))
	}
	return nil
}
func (h *handlers) enroll(ctx context.Context, _ string, raw any) (*output, error) {
	b, err := policy.ParsePeerEnrollment(raw)
	if err != nil {
		return nil, err
	}
	u, o, role, err := h.browser(ctx, false)
	if err != nil {
		return nil, err
	}
	mid, err := core.ParseOID(b.MachineID, "Invalid machine")
	if err != nil {
		return nil, err
	}
	m, err := h.app.FindOne(ctx, "machines", bson.M{"_id": mid, "deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return nil, err
	}
	if m == nil || !(m["user_id"] == u["_id"] || ((role == "owner" || role == "admin") && m["user_id"] == o)) {
		return nil, httpapi.Fail(403, "You cannot enroll this machine")
	}
	if m["enabled"] == false {
		return nil, httpapi.Fail(409, "Enable the machine before enrolling private access")
	}
	if err = h.indexes(ctx); err != nil {
		return nil, err
	}
	id := o.Hex() + ":" + mid.Hex()
	existing, err := h.app.FindOne(ctx, "private_peers", bson.M{"_id": id})
	if err != nil {
		return nil, err
	}
	if core.Truthy(existing, "credential_hash") {
		return nil, httpapi.Fail(409, "This machine already has a private client; revoke it before reinstalling")
	}
	prefs, err := h.preferences(ctx, o)
	if err != nil {
		return nil, err
	}
	custom := b.Hostname
	if custom == nil {
		custom = b.Alias
	}
	if custom != nil {
		if err = h.hostnameCheck(ctx, o, mid, *custom); err != nil {
			return nil, err
		}
	}
	var address string
	for attempt := 0; attempt < 8; attempt++ {
		used, err := h.app.FindAll(ctx, "private_peers", bson.M{"workspace_id": o})
		if err != nil {
			return nil, err
		}
		occupied := map[string]bool{}
		for _, p := range used {
			occupied[core.Str(p, "ip")] = true
		}
		if existing != nil {
			address = core.Str(existing, "ip")
		} else {
			address, err = policy.PrivateAddress(prefs.CIDR, mid.Hex(), occupied)
			if err != nil {
				return nil, httpapi.Fail(409, err.Error())
			}
		}
		set := bson.M{"workspace_id": o, "machine_id": mid, "owner_id": m["user_id"], "ip": address, "enabled": true, "updated_at": core.Now()}
		if custom != nil {
			set["hostname"] = *custom
		}
		_, err = h.app.C("private_peers").UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": set, "$setOnInsert": bson.M{"created_at": core.Now(), "revision": 0}}, options.UpdateOne().SetUpsert(true))
		if err == nil {
			break
		}
		if !mongo.IsDuplicateKeyError(err) {
			return nil, err
		}
		if custom != nil {
			clash, err := h.app.FindOne(ctx, "private_peers", bson.M{"workspace_id": o, "hostname": *custom, "_id": bson.M{"$ne": id}})
			if err != nil {
				return nil, err
			}
			if clash != nil {
				return nil, httpapi.Fail(409, "This private hostname is already in use")
			}
		}
		if attempt == 7 {
			return nil, httpapi.Fail(409, "Address allocation changed; retry enrollment")
		}
	}
	t := token()
	if _, err = h.app.C("private_install_tickets").UpdateMany(ctx, bson.M{"peer_id": id, "consumed_at": nil}, bson.M{"$set": bson.M{"consumed_at": core.Now()}}); err != nil {
		return nil, err
	}
	if _, err = h.app.C("private_install_tickets").InsertOne(ctx, bson.M{"_id": core.TokenDigest(t), "peer_id": id, "created_by": u["_id"], "consumed_at": nil, "expires_at": core.Now().Add(10 * time.Minute)}); err != nil {
		return nil, err
	}
	ms, ps, err := h.workspaceNames(ctx, o)
	if err != nil {
		return nil, err
	}
	short := core.RandomString(16)
	if _, err = h.app.C("machine_install_tickets").InsertOne(ctx, bson.M{"_id": core.TokenDigest(short), "machine_id": mid, "token_digest": core.TokenDigest(core.Str(m, "token")), "kind": "private", "private_ticket": t, "expires_at": core.Now().Add(10 * time.Minute)}); err != nil {
		return nil, err
	}
	command := "curl -fsSL " + h.app.PublicBaseURL(httpapi.Request(ctx)) + "/install/" + short + " | bash"
	return reply(map[string]any{"peer_id": id, "ip": address, "hostname": func() string { labels, _ := privateNames(ms, ps); return labels[id] }() + "." + prefs.DNSSuffix, "ticket": t, "expires_in": 600, "command": command}), nil
}
func (h *handlers) ownedPeer(ctx context.Context, id string) (core.Doc, bson.ObjectID, error) {
	u, o, role, err := h.browser(ctx, false)
	if err != nil {
		return nil, o, err
	}
	p, err := h.app.FindOne(ctx, "private_peers", bson.M{"_id": id, "workspace_id": o})
	if err != nil {
		return nil, o, err
	}
	if p == nil || ((role != "owner" && role != "admin") && p["owner_id"] != u["_id"]) {
		return nil, o, httpapi.Fail(404, "Private peer not found")
	}
	return p, o, nil
}
func (h *handlers) rename(ctx context.Context, id string, raw any) (*output, error) {
	name, err := policy.ParseHostnameChange(raw)
	if err != nil {
		return nil, err
	}
	p, o, err := h.ownedPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = h.indexes(ctx); err != nil {
		return nil, err
	}
	change := bson.M{"$set": bson.M{"updated_at": core.Now()}}
	if name != nil {
		if err = h.hostnameCheck(ctx, o, p["machine_id"], *name); err != nil {
			return nil, err
		}
		change["$set"].(bson.M)["hostname"] = *name
	} else {
		change["$unset"] = bson.M{"hostname": ""}
	}
	if _, err = h.app.C("private_peers").UpdateOne(ctx, bson.M{"_id": id}, change); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, httpapi.Fail(409, "This private hostname is already in use")
		}
		return nil, err
	}
	ms, ps, err := h.workspaceNames(ctx, o)
	if err != nil {
		return nil, err
	}
	return reply(map[string]any{"hostname": func() string { labels, _ := privateNames(ms, ps); return labels[id] }()}), nil
}
func (h *handlers) bootstrap(ctx context.Context, _ string, raw any) (*output, error) {
	t, err := policy.ParseToken(raw, "ticket")
	if err != nil {
		return nil, err
	}
	now := core.Now()
	var claim core.Doc
	err = h.app.C("private_install_tickets").FindOneAndUpdate(ctx, bson.M{"_id": core.TokenDigest(t), "consumed_at": nil, "expires_at": bson.M{"$gt": now}}, bson.M{"$set": bson.M{"consumed_at": now}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&claim)
	if isMissing(err) {
		return nil, httpapi.Fail(403, "Installer ticket is invalid, expired or already used")
	}
	if err != nil {
		return nil, err
	}
	p, err := h.app.FindOne(ctx, "private_peers", bson.M{"_id": claim["peer_id"], "enabled": true})
	if err != nil {
		return nil, err
	}
	if p == nil || core.Truthy(p, "credential_hash") {
		return nil, httpapi.Fail(403, "Private enrollment is no longer available")
	}
	if claim["created_by"] != p["workspace_id"] {
		m, err := h.app.FindOne(ctx, "workspace_members", bson.M{"_id": core.IDString(p["workspace_id"]) + ":" + core.IDString(claim["created_by"])})
		if err != nil {
			return nil, err
		}
		role := core.Str(m, "role")
		if role != "admin" && role != "member" {
			return nil, httpapi.Fail(403, "Installer issuer no longer belongs to the workspace")
		}
	}
	credential := token()
	r, err := h.app.C("private_peers").UpdateOne(ctx, bson.M{"_id": p["_id"], "enabled": true, "credential_hash": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"credential_hash": core.TokenDigest(credential), "credential_created_at": now}})
	if err != nil {
		return nil, err
	}
	if r.ModifiedCount != 1 {
		return nil, httpapi.Fail(409, "Enrollment was already completed")
	}
	out := reply(map[string]any{"peer_id": p["_id"], "token": credential, "workspace": core.IDString(p["workspace_id"])})
	out.CacheControl = "no-store"
	return out, nil
}
func (h *handlers) changePeer(ctx context.Context, id string, raw any) (*output, error) {
	enabled, err := policy.ParsePeerChange(raw)
	if err != nil {
		return nil, err
	}
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	r, err := h.app.C("private_peers").UpdateOne(ctx, bson.M{"_id": id, "workspace_id": o}, bson.M{"$set": bson.M{"enabled": enabled, "updated_at": core.Now()}})
	if err != nil {
		return nil, err
	}
	if r.MatchedCount == 0 {
		return nil, httpapi.Fail(404, "Private peer not found")
	}
	if enabled {
		return message("Private access enabled"), nil
	}
	return message("Private access disabled"), nil
}
func (h *handlers) revokePeer(ctx context.Context, id string, _ any) (*output, error) {
	if _, _, err := h.ownedPeer(ctx, id); err != nil {
		return nil, err
	}
	if _, err := h.app.C("private_peers").UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"enabled": false}, "$unset": bson.M{"credential_hash": "", "fingerprint": "", "instance": ""}}); err != nil {
		return nil, err
	}
	if _, err := h.app.C("private_install_tickets").UpdateMany(ctx, bson.M{"peer_id": id}, bson.M{"$set": bson.M{"consumed_at": core.Now()}}); err != nil {
		return nil, err
	}
	_, err := h.app.C("private_signals").DeleteMany(ctx, bson.M{"$or": bson.A{bson.M{"from": id}, bson.M{"to": id}}})
	return message("Private credential revoked; public access is unchanged"), err
}
