package machines

import (
	"context"
	"fmt"

	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/policy"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// EnsureDefaultPrivateNetworks migrates existing machines to automatic private
// enrollment. Revoked ownership and existing enrollments retain their state.
func EnsureDefaultPrivateNetworks(ctx context.Context, app *core.App) error {
	h := &h{app: app}
	machines, err := app.FindAll(ctx, "machines", bson.M{"deletion_pending": bson.M{"$ne": true}})
	if err != nil {
		return err
	}
	for _, machine := range machines {
		if err := h.ensurePrivateEnrollment(ctx, machine); err != nil {
			return fmt.Errorf("private enrollment for %s: %w", core.IDString(machine["_id"]), err)
		}
	}
	return nil
}

func (h *h) ensurePrivateEnrollment(ctx context.Context, machine core.Doc) error {
	if core.Truthy(machine, "private_owner_revoked") {
		return nil
	}
	// A machine already enrolled in an invited workspace keeps that workspace.
	existing, err := h.app.FindOne(ctx, "private_peers", bson.M{"machine_id": machine["_id"], "owner_id": machine["user_id"]})
	if err != nil || existing != nil {
		return err
	}
	owner := machine["user_id"]
	prefsDoc, err := h.app.FindOne(ctx, "private_networks", bson.M{"_id": core.IDString(owner)})
	if err != nil {
		return err
	}
	if prefsDoc == nil {
		prefsDoc = core.Doc{}
	}
	prefs, err := policy.ParseNetworkPreferences(prefsDoc)
	if err != nil {
		return err
	}
	coll := h.app.C("private_peers")
	if _, err = coll.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: core.Sort("workspace_id", 1, "ip", 1), Options: options.Index().SetUnique(true)}); err != nil {
		return err
	}
	id := core.IDString(owner) + ":" + core.IDString(machine["_id"])
	for attempt := 0; attempt < 8; attempt++ {
		peers, err := h.app.FindAll(ctx, "private_peers", bson.M{"workspace_id": owner})
		if err != nil {
			return err
		}
		occupied := map[string]bool{}
		for _, peer := range peers {
			occupied[core.Str(peer, "ip")] = true
			if peer["_id"] == id {
				return nil
			}
		}
		ip, err := policy.PrivateAddress(prefs.CIDR, core.IDString(machine["_id"]), occupied)
		if err != nil {
			return err
		}
		now := core.Now()
		_, err = coll.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$setOnInsert": bson.M{"workspace_id": owner, "owner_id": owner, "machine_id": machine["_id"], "ip": ip, "enabled": true, "revision": 0, "created_at": now, "updated_at": now}}, options.UpdateOne().SetUpsert(true))
		if err == nil {
			return nil
		}
		if !mongo.IsDuplicateKeyError(err) {
			return err
		}
	}
	return fmt.Errorf("private address allocation changed; retry")
}
