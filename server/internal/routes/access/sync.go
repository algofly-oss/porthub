package access

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/algofly-oss/porthub/server/internal/core"
	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"github.com/algofly-oss/porthub/server/internal/routes/access/policy"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const relayURL = "turn:relay.porthub.invalid:443?transport=tcp"

func iceServers(peerID string) []any {
	servers := []any{}
	var raw []any
	_ = json.Unmarshal([]byte(os.Getenv("PORTHUB_PRIVATE_ICE_SERVERS")), &raw)
	for _, v := range raw {
		d, ok := v.(map[string]any)
		if !ok {
			continue
		}
		urls, ok := d["urls"].([]any)
		if !ok {
			continue
		}
		valid := true
		for _, u := range urls {
			s, ok := u.(string)
			if !ok {
				valid = false
				break
			}
			scheme, _, _ := strings.Cut(s, ":")
			if scheme != "stun" && scheme != "turn" && scheme != "turns" {
				valid = false
				break
			}
		}
		if valid {
			servers = append(servers, d)
		}
	}
	if secret := os.Getenv("PORTHUB_RELAY_SECRET"); len([]rune(secret)) >= 32 && peerID != "" {
		username := fmt.Sprintf("%d:%s", time.Now().Unix()+12*3600, peerID)
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(username))
		servers = append(servers, map[string]any{"urls": []string{relayURL}, "username": username, "credential": base64.StdEncoding.EncodeToString(mac.Sum(nil))})
	}
	return servers
}
func relayRoutes() []string {
	out := []string{}
	for _, s := range strings.Split(os.Getenv("PORTHUB_RELAY_ROUTES"), ",") {
		s = strings.TrimRight(policy.PyStrip(s), "/")
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			out = append(out, s)
			if len(out) == 4 {
				break
			}
		}
	}
	return out
}
func (h *handlers) activeInventory(ctx context.Context, o bson.ObjectID) ([]core.Doc, map[string]core.Doc, error) {
	ps, err := h.app.FindAll(ctx, "private_peers", bson.M{"workspace_id": o, "enabled": true})
	if err != nil {
		return nil, nil, err
	}
	ids := []any{}
	for _, p := range ps {
		ids = append(ids, p["machine_id"])
	}
	ms, err := h.app.FindAll(ctx, "machines", bson.M{"_id": bson.M{"$in": ids}, "enabled": bson.M{"$ne": false}, "deletion_pending": bson.M{"$ne": true}, "private_owner_revoked": bson.M{"$ne": true}})
	if err != nil {
		return nil, nil, err
	}
	members, err := h.app.FindAll(ctx, "workspace_members", bson.M{"workspace_id": o, "role": bson.M{"$in": bson.A{"member", "admin"}}})
	if err != nil {
		return nil, nil, err
	}
	valid := map[string]bool{o.Hex(): true}
	for _, m := range members {
		valid[core.IDString(m["user_id"])] = true
	}
	inventory := map[string]core.Doc{}
	for _, m := range ms {
		inventory[core.IDString(m["_id"])] = m
	}
	active := []core.Doc{}
	for _, p := range ps {
		if inventory[core.IDString(p["machine_id"])] != nil && valid[core.IDString(p["owner_id"])] {
			active = append(active, p)
		}
	}
	return active, inventory, nil
}

var fingerprintLines = regexp.MustCompile(`(?m)^a=fingerprint:sha-256 ([^\r\n]+)`)

func validateSignal(source, target string, s policy.Signal, fingerprint string) error {
	if (s.Description.Type == "offer") != (source < target) {
		return httpapi.Fail(400, "Invalid peer negotiation direction")
	}
	matches := fingerprintLines.FindAllStringSubmatch(s.Description.SDP, -1)
	if len(matches) == 0 {
		return httpapi.Fail(400, "Signaling certificate does not match the enrolled client")
	}
	for _, m := range matches {
		if strings.ToUpper(m[1]) != fingerprint {
			return httpapi.Fail(400, "Signaling certificate does not match the enrolled client")
		}
	}
	return nil
}
func (h *handlers) sync(ctx context.Context, _ string, raw any) (*output, error) {
	b, err := policy.ParseClientSync(raw)
	if err != nil {
		return nil, err
	}
	peer, err := h.app.FindOne(ctx, "private_peers", bson.M{"_id": b.PeerID, "credential_hash": core.TokenDigest(b.Token), "enabled": true})
	if err != nil {
		return nil, err
	}
	if peer == nil {
		return nil, httpapi.Fail(403, "Private credential invalid or revoked")
	}
	o, _ := core.AsOID(peer["workspace_id"])
	ps, inventory, err := h.activeInventory(ctx, o)
	if err != nil {
		return nil, err
	}
	found := false
	for _, p := range ps {
		if p["_id"] == b.PeerID {
			found = true
		}
	}
	if !found {
		return nil, httpapi.Fail(403, "Machine or workspace membership is disabled")
	}
	if len(b.Paths) > 1000 {
		return nil, httpapi.Fail(400, "Too many path reports")
	}
	now := core.Now()
	var updated core.Doc
	err = h.app.C("private_peers").FindOneAndUpdate(ctx, bson.M{"_id": b.PeerID, "enabled": true, "credential_hash": peer["credential_hash"]}, bson.M{"$set": bson.M{"fingerprint": b.Fingerprint, "instance": b.Instance, "last_seen_at": now, "paths": b.Paths}, "$inc": bson.M{"revision": 1}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&updated)
	if isMissing(err) {
		return nil, httpapi.Fail(403, "Private credential revoked")
	}
	if err != nil {
		return nil, err
	}
	for i, p := range ps {
		if p["_id"] == b.PeerID {
			ps[i] = updated
		}
	}
	gs, err := h.app.FindAll(ctx, "machine_groups", bson.M{"user_id": o})
	if err != nil {
		return nil, err
	}
	books, err := h.app.FindAll(ctx, "access_rulebooks", bson.M{"user_id": o})
	if err != nil {
		return nil, err
	}
	machines := []map[string]any{}
	mapping := map[string]string{}
	for _, p := range ps {
		mid := core.IDString(p["machine_id"])
		m := core.Doc{}
		for k, v := range inventory[mid] {
			m[k] = v
		}
		m["user_id"] = o
		m["private_owner_id"] = p["owner_id"]
		machines = append(machines, m)
		mapping[mid] = core.IDString(p["_id"])
	}
	grants := []policy.Grant{}
	reachable := map[string]bool{b.PeerID: true}
	for _, g := range policy.CompileGrants(machines, docs(books), groupMap(gs)) {
		g.Source = mapping[g.Source]
		g.Destination = mapping[g.Destination]
		if g.Source == b.PeerID || g.Destination == b.PeerID {
			grants = append(grants, g)
			reachable[g.Source] = true
			reachable[g.Destination] = true
		}
	}
	byID := map[string]core.Doc{}
	reachableIDs := []string{}
	for _, p := range ps {
		id := core.IDString(p["_id"])
		if reachable[id] {
			byID[id] = p
			reachableIDs = append(reachableIDs, id)
		}
	}
	for _, s := range b.Signals {
		target := byID[s.To]
		if target == nil || s.To == b.PeerID || !core.Truthy(target, "fingerprint") {
			continue
		}
		if err = validateSignal(b.PeerID, s.To, s, b.Fingerprint); err != nil {
			return nil, err
		}
		id := core.TokenDigest(b.PeerID + ":" + b.Instance + ":" + s.To + ":" + s.Session + ":" + s.Description.Type)
		_, err = h.app.C("private_signals").UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$setOnInsert": bson.M{"from": b.PeerID, "to": s.To, "source_instance": b.Instance, "target_instance": target["instance"], "session": s.Session, "fingerprint": b.Fingerprint, "description": s.Description.Dict(), "expires_at": now.Add(45 * time.Second)}}, options.UpdateOne().SetUpsert(true))
		if err != nil {
			return nil, err
		}
	}
	if len(b.Acks) > 0 {
		if _, err = h.app.C("private_signals").DeleteMany(ctx, bson.M{"_id": bson.M{"$in": b.Acks}, "to": b.PeerID}); err != nil {
			return nil, err
		}
	}
	incoming, err := h.app.FindAll(ctx, "private_signals", bson.M{"to": b.PeerID, "target_instance": b.Instance, "from": bson.M{"$in": reachableIDs}, "expires_at": bson.M{"$gt": now}}, options.Find().SetLimit(128))
	if err != nil {
		return nil, err
	}
	signals := []any{}
	for _, s := range incoming {
		source := byID[core.Str(s, "from")]
		if source != nil && s["source_instance"] == source["instance"] && s["fingerprint"] == source["fingerprint"] {
			signals = append(signals, map[string]any{"id": s["_id"], "from": s["from"], "session": s["session"], "description": core.JSON(s["description"])})
		}
	}
	prefs, err := h.preferences(ctx, o)
	if err != nil {
		return nil, err
	}
	ms, all, err := h.workspaceNames(ctx, o)
	if err != nil {
		return nil, err
	}
	labels, aliases := privateNames(ms, all)
	peerOut := []any{}
	for _, p := range ps {
		id := core.IDString(p["_id"])
		if !reachable[id] {
			continue
		}
		aa := []string{}
		for _, a := range aliases[id] {
			aa = append(aa, a+"."+prefs.DNSSuffix)
		}
		peerOut = append(peerOut, map[string]any{"id": id, "ip": p["ip"], "fingerprint": core.Get(p, "fingerprint", ""), "instance": core.Get(p, "instance", ""), "hostname": labels[id] + "." + prefs.DNSSuffix, "aliases": aa})
	}
	out := reply(map[string]any{"snapshot": map[string]any{"workspace": o.Hex(), "self": b.PeerID, "revision": updated["revision"], "expires_at": now.Add(15 * time.Second), "peers": peerOut, "grants": grants}, "signals": signals, "ice_servers": iceServers(b.PeerID), "relay_routes": relayRoutes(), "poll_seconds": 1})
	out.CacheControl = "no-store"
	return out, nil
}
