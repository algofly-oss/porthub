package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/algofly-oss/porthub/server/internal/httpapi"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Workspace membership (shared/workspaces.py). Legacy user-owned inventory
// keeps user_id = the workspace owner's id.

func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// WorkspaceAccess mirrors workspace_access: (owner id, role).
func (a *App) WorkspaceAccess(ctx context.Context, user Doc, workspaceID string, manage bool) (bson.ObjectID, string, error) {
	userID, _ := AsOID(user["_id"])
	owner := userID
	if workspaceID != "" {
		id, err := bson.ObjectIDFromHex(workspaceID)
		if err != nil {
			return owner, "", httpapi.Fail(400, "Invalid workspace")
		}
		owner = id
	}
	role := "owner"
	if owner != userID {
		m, err := a.FindOne(ctx, "workspace_members", bson.M{"_id": owner.Hex() + ":" + userID.Hex()})
		if err != nil {
			return owner, "", err
		}
		r := Str(m, "role")
		if m == nil || (r != "admin" && r != "member") {
			return owner, "", httpapi.Fail(403, "You do not belong to this workspace")
		}
		role = r
	}
	if manage && role != "owner" && role != "admin" {
		return owner, role, httpapi.Fail(403, "Workspace administrator permission is required")
	}
	return owner, role, nil
}

// ValidInvitation mirrors valid_invitation.
func (a *App) ValidInvitation(ctx context.Context, token string) (Doc, error) {
	if n := len([]rune(token)); n < 32 || n > 200 {
		return nil, httpapi.Fail(400, "Invitation is invalid or expired")
	}
	invite, err := a.FindOne(ctx, "workspace_invites", bson.M{"_id": TokenDigest(token), "consumed_at": nil, "revoked_at": nil,
		"expires_at": bson.M{"$gt": Now()}})
	if err != nil {
		return nil, err
	}
	if invite == nil {
		return nil, httpapi.Fail(400, "Invitation is invalid or expired")
	}
	return invite, nil
}

// AcceptInvitation mirrors accept_invitation and returns the workspace id.
func (a *App) AcceptInvitation(ctx context.Context, user Doc, token string) (string, error) {
	invite, err := a.ValidInvitation(ctx, token)
	if err != nil {
		return "", err
	}
	if strings.ToLower(strings.TrimSpace(Str(user, "username"))) != Str(invite, "email") {
		return "", httpapi.Fail(403, "Sign in with the email address this invitation was sent to")
	}
	owner := invite["user_id"]
	if IDString(owner) == IDString(user["_id"]) {
		return "", httpapi.Fail(400, "You already own this workspace")
	}
	issuer := invite["created_by"]
	issuerRole := "owner"
	if IDString(issuer) != IDString(owner) {
		m, err := a.FindOne(ctx, "workspace_members", bson.M{"_id": IDString(owner) + ":" + IDString(issuer)})
		if err != nil {
			return "", err
		}
		issuerRole = Str(m, "role")
	}
	if (issuerRole != "owner" && issuerRole != "admin") || (Str(invite, "role") == "admin" && issuerRole != "owner") {
		return "", httpapi.Fail(403, "The invitation issuer no longer has permission")
	}
	claim, err := a.C("workspace_invites").UpdateOne(ctx,
		bson.M{"_id": invite["_id"], "consumed_at": nil, "revoked_at": nil, "expires_at": bson.M{"$gt": Now()}},
		bson.M{"$set": bson.M{"consumed_at": Now(), "accepted_by": user["_id"]}})
	if err != nil {
		return "", err
	}
	if claim.ModifiedCount != 1 {
		return "", httpapi.Fail(409, "Invitation has already been used or revoked")
	}
	_, err = a.C("workspace_members").UpdateOne(ctx, bson.M{"_id": IDString(owner) + ":" + IDString(user["_id"])},
		bson.M{"$setOnInsert": bson.M{"user_id": user["_id"], "workspace_id": owner, "role": invite["role"], "joined_at": Now()}},
		options.UpdateOne().SetUpsert(true))
	if err != nil {
		_, _ = a.C("workspace_invites").UpdateOne(ctx, bson.M{"_id": invite["_id"], "accepted_by": user["_id"]},
			bson.M{"$set": bson.M{"consumed_at": nil}, "$unset": bson.M{"accepted_by": ""}})
		return "", err
	}
	return IDString(owner), nil
}
