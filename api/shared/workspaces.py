"""Workspace membership is separate from the installation-wide admin role.

Legacy user-owned inventory remains unchanged: its user_id is the workspace
owner's ID. Sharing is exposed only through explicitly workspace-aware APIs.
"""

import hashlib
from datetime import datetime

from bson import ObjectId
from fastapi import HTTPException

from shared.factory import db


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def workspace_access(user, workspace_id=None, *, manage=False):
    try:
        owner_id = ObjectId(workspace_id) if workspace_id else user["_id"]
    except Exception:
        raise HTTPException(400, "Invalid workspace")
    if str(owner_id) == str(user["_id"]):
        role = "owner"
    else:
        membership = await db.workspace_members.find_one(
            {"_id": f"{owner_id}:{user['_id']}"}
        )
        if not membership or membership.get("role") not in {"admin", "member"}:
            raise HTTPException(403, "You do not belong to this workspace")
        role = membership["role"]
    if manage and role not in {"owner", "admin"}:
        raise HTTPException(403, "Workspace administrator permission is required")
    return owner_id, role


async def valid_invitation(token):
    if not isinstance(token, str) or not 32 <= len(token) <= 200:
        raise HTTPException(400, "Invitation is invalid or expired")
    invite = await db.workspace_invites.find_one(
        {
            "_id": token_digest(token),
            "consumed_at": None,
            "revoked_at": None,
            "expires_at": {"$gt": datetime.utcnow()},
        }
    )
    if not invite:
        raise HTTPException(400, "Invitation is invalid or expired")
    return invite


async def accept_invitation(user, token):
    invite = await valid_invitation(token)
    if str(user.get("username", "")).strip().lower() != invite["email"]:
        raise HTTPException(
            403, "Sign in with the email address this invitation was sent to"
        )
    owner_id = invite["user_id"]
    if str(owner_id) == str(user["_id"]):
        raise HTTPException(400, "You already own this workspace")
    # A removed administrator must not retain outstanding invitations.
    issuer = invite["created_by"]
    issuer_role = (
        "owner"
        if issuer == owner_id
        else (
            await db.workspace_members.find_one({"_id": f"{owner_id}:{issuer}"}) or {}
        ).get("role")
    )
    if issuer_role not in {"owner", "admin"} or (
        invite["role"] == "admin" and issuer_role != "owner"
    ):
        raise HTTPException(403, "The invitation issuer no longer has permission")
    member_key = f"{owner_id}:{user['_id']}"
    # Idempotent membership insert, never a privilege-changing update. The
    # invite token must be claimed atomically before granting membership.
    claim = await db.workspace_invites.update_one(
        {
            "_id": invite["_id"],
            "consumed_at": None,
            "revoked_at": None,
            "expires_at": {"$gt": datetime.utcnow()},
        },
        {"$set": {"consumed_at": datetime.utcnow(), "accepted_by": user["_id"]}},
    )
    if claim.modified_count != 1:
        raise HTTPException(409, "Invitation has already been used or revoked")
    try:
        await db.workspace_members.update_one(
            {"_id": member_key},
            {
                "$setOnInsert": {
                    "user_id": user["_id"],
                    "workspace_id": owner_id,
                    "role": invite["role"],
                    "joined_at": datetime.utcnow(),
                }
            },
            upsert=True,
        )
    except Exception:
        # Retrying with the same intended recipient is safe if the insert
        # failed; a successful insert cannot elevate an existing membership.
        await db.workspace_invites.update_one(
            {"_id": invite["_id"], "accepted_by": user["_id"]},
            {"$set": {"consumed_at": None}, "$unset": {"accepted_by": ""}},
        )
        raise
    return str(owner_id)
