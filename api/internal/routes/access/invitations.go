package access

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/algofly-oss/porthub/api/internal/core"
	"github.com/algofly-oss/porthub/api/internal/httpapi"
	"github.com/algofly-oss/porthub/api/internal/policy"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func isMissing(err error) bool { return errors.Is(err, mongo.ErrNoDocuments) }
func token() string            { return base64.RawURLEncoding.EncodeToString(randBytes()) }
func randBytes() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func (h *handlers) invite(ctx context.Context, _ string, raw any) (*output, error) {
	b, err := policy.ParseInvite(raw)
	if err != nil {
		return nil, err
	}
	u, o, role, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	if b.Role == "admin" && role != "owner" {
		return nil, httpapi.Fail(403, "Only the owner can invite administrators")
	}
	n, err := h.app.C("workspace_invites").CountDocuments(ctx, bson.M{"user_id": o, "consumed_at": nil, "revoked_at": nil, "expires_at": bson.M{"$gt": core.Now()}})
	if err != nil {
		return nil, err
	}
	if n >= 100 {
		return nil, httpapi.Fail(400, "Revoke an outstanding invitation before creating more")
	}
	t := token()
	expires := core.Now().Add(7 * 24 * time.Hour)
	_, err = h.app.C("workspace_invites").InsertOne(ctx, bson.M{"_id": core.TokenDigest(t), "user_id": o, "email": b.Email, "role": b.Role, "created_by": u["_id"], "created_at": core.Now(), "expires_at": expires, "consumed_at": nil, "revoked_at": nil})
	return reply(map[string]any{"token": t, "expires_at": core.JSON(expires)}), err
}
func (h *handlers) revokeInvite(ctx context.Context, id string, _ any) (*output, error) {
	_, o, _, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	_, err = h.app.C("workspace_invites").UpdateOne(ctx, bson.M{"_id": id, "user_id": o, "consumed_at": nil}, bson.M{"$set": bson.M{"revoked_at": core.Now()}})
	return message("Invitation revoked"), err
}
func (h *handlers) previewInvite(ctx context.Context, _ string, raw any) (*output, error) {
	t, err := policy.ParseToken(raw, "token")
	if err != nil {
		return nil, err
	}
	i, err := h.app.ValidInvitation(ctx, t)
	if err != nil {
		return nil, err
	}
	o, err := h.app.FindOne(ctx, "users", bson.M{"_id": i["user_id"]})
	if err != nil {
		return nil, err
	}
	return reply(map[string]any{"email": i["email"], "role": i["role"], "workspace": core.Get(o, "name", "PortHub"), "expires_at": core.JSON(i["expires_at"])}), nil
}
func (h *handlers) acceptInvite(ctx context.Context, _ string, raw any) (*output, error) {
	t, err := policy.ParseToken(raw, "token")
	if err != nil {
		return nil, err
	}
	if err = checkOrigin(httpapi.Request(ctx)); err != nil {
		return nil, err
	}
	u, err := h.app.User(ctx)
	if err != nil {
		return nil, err
	}
	o, err := h.app.AcceptInvitation(ctx, u, t)
	return reply(map[string]any{"workspace_id": o}), err
}
func (h *handlers) removeMember(ctx context.Context, id string, _ any) (*output, error) {
	u, o, role, err := h.browser(ctx, true)
	if err != nil {
		return nil, err
	}
	target, err := core.ParseOID(id, "Invalid member")
	if err != nil {
		return nil, err
	}
	if target == o {
		return nil, httpapi.Fail(400, "The workspace owner cannot be removed")
	}
	key := o.Hex() + ":" + target.Hex()
	m, err := h.app.FindOne(ctx, "workspace_members", bson.M{"_id": key})
	if err != nil {
		return nil, err
	}
	if core.Str(m, "role") == "admin" && role != "owner" {
		return nil, httpapi.Fail(403, "Only the owner can remove administrators")
	}
	if target == u["_id"] {
		return nil, httpapi.Fail(400, "Ask the workspace owner to remove your administrative membership")
	}
	if _, err = h.app.C("workspace_members").DeleteOne(ctx, bson.M{"_id": key}); err != nil {
		return nil, err
	}
	if _, err = h.app.C("machines").UpdateMany(ctx, bson.M{"user_id": o, "private_owner_id": target}, bson.M{"$set": bson.M{"private_owner_revoked": true}}); err != nil {
		return nil, err
	}
	if _, err = h.app.C("machine_groups").UpdateMany(ctx, bson.M{"user_id": o}, bson.M{"$pull": bson.M{"user_ids": target}}); err != nil {
		return nil, err
	}
	_, err = h.app.C("workspace_invites").UpdateMany(ctx, bson.M{"user_id": o, "created_by": target, "consumed_at": nil}, bson.M{"$set": bson.M{"revoked_at": core.Now()}})
	return message("Member removed"), err
}
