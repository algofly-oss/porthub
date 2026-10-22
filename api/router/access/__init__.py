"""Private-network control plane. No routes, tunnels or public policies changed."""

import secrets
from datetime import timedelta
from typing import Literal
from urllib.parse import urlsplit

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, validator
from pymongo import ReturnDocument

from router.common import (
    get_authenticated_user,
    get_machine_group_object_ids,
    get_machine_connection_status,
    parse_object_id,
    utcnow,
)
from shared.access_policy import RuleBook, NetworkPreferences, evaluate_access
from shared.factory import db
from shared.workspaces import (
    workspace_access,
    token_digest,
    valid_invitation,
    accept_invitation,
)

router = APIRouter(prefix="/access", tags=["Private access control"])

from .private import router as private_router
router.include_router(private_router)


def check_origin(request):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                valid = (
                    parsed.scheme in {"http", "https"}
                    and parsed.netloc.lower() == request.headers.get("host", "").lower()
                )
            except ValueError:
                valid = False
            if not valid:
                raise HTTPException(
                    403, "Cross-origin workspace changes are not allowed"
                )


async def context(request, manage=False):
    check_origin(request)
    user = await get_authenticated_user(request)
    owner, role = await workspace_access(
        user, request.query_params.get("workspace"), manage=manage
    )
    return user, owner, role


def clean_doc(document):
    return {
        key: str(value) if isinstance(value, ObjectId) else value
        for key, value in document.items()
    }


async def member_ids(owner):
    memberships = await db.workspace_members.find({"workspace_id": owner}).to_list(None)
    return [owner, *[entry["user_id"] for entry in memberships]], memberships


@router.get("/workspaces")
async def workspaces(request: Request):
    user = await get_authenticated_user(request)
    memberships = await db.workspace_members.find({"user_id": user["_id"]}).to_list(
        None
    )
    owners = await db.users.find(
        {
            "_id": {
                "$in": [user["_id"], *[entry["workspace_id"] for entry in memberships]]
            }
        },
        {"name": 1, "username": 1},
    ).to_list(None)
    roles = {str(entry["workspace_id"]): entry["role"] for entry in memberships}
    roles[str(user["_id"])] = "owner"
    return {
        "data": [
            {
                "id": str(owner["_id"]),
                "name": f"{owner.get('name') or owner.get('username')}'s Workspace",
                "role": roles[str(owner["_id"])],
            }
            for owner in owners
        ]
    }


@router.get("/snapshot")
async def snapshot(request: Request):
    _, owner, role = await context(request)
    machines = await db.machines.find(
        {"user_id": owner, "deletion_pending": {"$ne": True}}
    ).to_list(None)
    groups = (
        await db.machine_groups.find({"user_id": owner})
        .sort([("sort_order", 1), ("name", 1)])
        .to_list(None)
    )
    ids, memberships = await member_ids(owner)
    users = await db.users.find(
        {"_id": {"$in": ids}}, {"name": 1, "username": 1}
    ).to_list(None)
    roles = {str(entry["user_id"]): entry["role"] for entry in memberships}
    roles[str(owner)] = "owner"
    books = (
        await db.access_rulebooks.find({"user_id": owner})
        .sort("created_at", 1)
        .to_list(None)
    )
    preferences = await db.private_networks.find_one({"_id": str(owner)})
    from .private import workspace_names
    from shared.private_overlay import assign_hostnames
    name_machines, peers = await workspace_names(owner)
    labels = assign_hostnames(name_machines, peers)
    machine_names = {m["_id"]: m.get("name", "") for m in name_machines}
    now = utcnow()
    invites = (
        await db.workspace_invites.find(
            {
                "user_id": owner,
                "consumed_at": None,
                "revoked_at": None,
                "expires_at": {"$gt": utcnow()},
            },
            {"email": 1, "role": 1, "expires_at": 1},
        ).to_list(None)
        if role in {"owner", "admin"}
        else []
    )
    # Explicit whitelist: invited members never receive enrollment tokens,
    # script URLs, password hashes, API credentials or log tokens.
    return {
        "workspace_id": str(owner),
        "role": role,
        "transport_ready": False,
        "network": NetworkPreferences(**(preferences or {})).dict(),
        "machines": [
            {
                "_id": str(m["_id"]),
                "name": m.get("name", ""),
                "group_ids": [str(g) for g in get_machine_group_object_ids(m)],
                "private_owner_id": str(m.get("private_owner_id") or owner),
                "private_owner_revoked": bool(m.get("private_owner_revoked")),
                "enabled": m.get("enabled", True),
                "connection_status": get_machine_connection_status(m),
            }
            for m in machines
        ],
        "users": [
            {
                "_id": str(u["_id"]),
                "name": u.get("name", ""),
                "email": u.get("username", ""),
                "role": roles[str(u["_id"])],
            }
            for u in users
        ],
        "groups": [
            {
                "_id": str(g["_id"]),
                "name": g.get("name", ""),
                "user_ids": [str(uid) for uid in g.get("user_ids", []) if uid in ids],
            }
            for g in groups
        ],
        "books": [clean_doc(book) for book in books],
        # Whitelisted private peer fields only: never credentials or SDP.
        "private_peers": [
            {
                "_id": p["_id"],
                "machine_id": str(p["machine_id"]),
                "machine_name": machine_names.get(p["machine_id"], ""),
                "ip": p["ip"],
                "hostname": labels[p["_id"]],
                "custom_hostname": bool(p.get("hostname")),
                "enabled": p.get("enabled", True),
                "installed": bool(p.get("credential_hash")),
                "online": bool(p.get("last_seen_at") and (now - p["last_seen_at"]).total_seconds() < 30),
                "last_seen_at": p.get("last_seen_at"),
                "paths": sorted(set((p.get("paths") or {}).values())),
            }
            for p in sorted(peers, key=lambda p: labels[p["_id"]])
        ],
        "invitations": [clean_doc(invite) for invite in invites],
    }


async def validate_selectors(book, owner):
    group_ids = {book.group_id}
    selectors = [s for rule in book.rules for s in [*rule.sources, *rule.destinations]]
    group_ids.update(s.id for s in selectors if s.kind == "group")
    for kind, ids in [
        ("group", group_ids),
        ("machine", {s.id for s in selectors if s.kind == "machine"}),
    ]:
        oids = [parse_object_id(value, f"Invalid {kind} identifier") for value in ids]
        collection = db.machine_groups if kind == "group" else db.machines
        found = (
            await collection.count_documents({"user_id": owner, "_id": {"$in": oids}})
            if oids
            else 0
        )
        if found != len(set(oids)):
            raise HTTPException(
                400, f"Every selected {kind} must belong to this workspace"
            )
    members, _ = await member_ids(owner)
    allowed = {str(uid) for uid in members}
    if any(s.id not in allowed for s in selectors if s.kind == "user"):
        raise HTTPException(400, "Selected users must belong to this workspace")


@router.post("/books")
async def create_book(data: RuleBook, request: Request):
    user, owner, _ = await context(request, True)
    await validate_selectors(data, owner)
    if await db.access_rulebooks.count_documents({"user_id": owner}) >= 100:
        raise HTTPException(400, "A workspace can have up to 100 rule books")
    now = utcnow()
    document = {
        **data.dict(),
        "revision": 1,
        "user_id": owner,
        "created_by": user["_id"],
        "created_at": now,
        "updated_at": now,
    }
    result = await db.access_rulebooks.insert_one(document)
    return {"data": {**clean_doc(document), "_id": str(result.inserted_id)}}


@router.put("/books/{book_id}")
async def update_book(book_id: str, data: RuleBook, request: Request):
    _, owner, _ = await context(request, True)
    await validate_selectors(data, owner)
    updated = await db.access_rulebooks.find_one_and_update(
        {
            "_id": parse_object_id(book_id, "Invalid rule book"),
            "user_id": owner,
            "revision": data.revision,
        },
        {
            "$set": {**data.dict(exclude={"revision"}), "updated_at": utcnow()},
            "$inc": {"revision": 1},
        },
        return_document=ReturnDocument.AFTER,
    )
    if not updated:
        raise HTTPException(
            409, "Rule book changed or no longer exists. Reload before saving."
        )
    return {"data": clean_doc(updated)}


class DeleteBook(BaseModel):
    revision: int = Field(..., ge=1)


@router.delete("/books/{book_id}")
async def delete_book(book_id: str, data: DeleteBook, request: Request):
    _, owner, _ = await context(request, True)
    deleted = await db.access_rulebooks.delete_one(
        {
            "_id": parse_object_id(book_id, "Invalid rule book"),
            "user_id": owner,
            "revision": data.revision,
        }
    )
    if deleted.deleted_count != 1:
        raise HTTPException(
            409, "Rule book changed or no longer exists. Reload before deleting."
        )
    return {"msg": "Rule book deleted"}


class GroupMembers(BaseModel):
    machine_ids: list[str] = Field(default_factory=list, max_items=1000)
    user_ids: list[str] = Field(default_factory=list, max_items=1000)


@router.put("/groups/{group_id}/members")
async def group_members(group_id: str, data: GroupMembers, request: Request):
    _, owner, _ = await context(request, True)
    gid = parse_object_id(group_id, "Invalid group")
    group = await db.machine_groups.find_one({"_id": gid, "user_id": owner})
    if not group:
        raise HTTPException(404, "Group not found")
    machine_ids = list(
        {parse_object_id(mid, "Invalid machine") for mid in data.machine_ids}
    )
    user_ids = list({parse_object_id(uid, "Invalid user") for uid in data.user_ids})
    if machine_ids and await db.machines.count_documents(
        {"_id": {"$in": machine_ids}, "user_id": owner}
    ) != len(machine_ids):
        raise HTTPException(400, "Selected machines must belong to this workspace")
    members, _ = await member_ids(owner)
    if not set(user_ids).issubset(set(members)):
        raise HTTPException(400, "Selected users must belong to this workspace")
    # Normalise legacy memberships with a compare-and-swap, then change only
    # this tag. Never overwrite other groups from a stale full-fleet snapshot.
    all_machines = await db.machines.find({"user_id": owner}).to_list(None)
    for machine in all_machines:
        if machine.get("group_id") and not machine.get("group_ids"):
            await db.machines.update_one(
                {
                    "_id": machine["_id"],
                    "user_id": owner,
                    "group_ids": machine.get("group_ids"),
                },
                {
                    "$set": {"group_ids": get_machine_group_object_ids(machine)},
                    "$unset": {"group_id": ""},
                },
            )
    if machine_ids:
        await db.machines.update_many(
            {"user_id": owner, "_id": {"$in": machine_ids}},
            {"$addToSet": {"group_ids": gid}},
        )
    await db.machines.update_many(
        {"user_id": owner, "_id": {"$nin": machine_ids}},
        {"$pull": {"group_ids": {"$in": [gid, str(gid)]}}},
    )
    await db.machine_groups.update_one(
        {"_id": gid, "user_id": owner},
        {"$set": {"user_ids": user_ids, "updated_at": utcnow()}},
    )
    return {"msg": "Group members saved"}


@router.post("/groups")
async def create_group(data: dict, request: Request):
    _, owner, _ = await context(request, True)
    name = str(data.get("name", "")).strip()
    if not name or len(name) > 80:
        raise HTTPException(400, "Group name must contain 1–80 characters")
    if await db.machine_groups.count_documents({"user_id": owner, "name": name}):
        raise HTTPException(409, "A group with that name already exists")
    result = await db.machine_groups.insert_one(
        {
            "user_id": owner,
            "name": name,
            "user_ids": [],
            "sort_order": 0,
            "created_at": utcnow(),
        }
    )
    return {"data": {"_id": str(result.inserted_id), "name": name, "user_ids": []}}


@router.put("/network")
async def network_preferences(data: NetworkPreferences, request: Request):
    _, owner, _ = await context(request, True)
    await db.private_networks.update_one(
        {"_id": str(owner)},
        {"$set": {**data.dict(), "updated_at": utcnow()}},
        upsert=True,
    )
    return {"data": data.dict(), "transport_ready": False}


class ConnectionTest(BaseModel):
    source_id: str
    destination_id: str
    protocol: Literal["tcp", "udp", "icmp"] = "tcp"
    port: int = Field(443, ge=1, le=65535)


@router.post("/test")
async def connection_test(data: ConnectionTest, request: Request):
    _, owner, _ = await context(request)
    machines = await db.machines.find(
        {
            "user_id": owner,
            "_id": {
                "$in": [
                    parse_object_id(data.source_id, "Invalid source"),
                    parse_object_id(data.destination_id, "Invalid destination"),
                ]
            },
        }
    ).to_list(None)
    by_id = {str(m["_id"]): m for m in machines}
    if data.source_id not in by_id or data.destination_id not in by_id:
        raise HTTPException(404, "Select two machines in this workspace")
    books = await db.access_rulebooks.find({"user_id": owner}).to_list(None)
    groups = await db.machine_groups.find({"user_id": owner}).to_list(None)
    return {
        "data": evaluate_access(
            by_id[data.source_id],
            by_id[data.destination_id],
            data.protocol,
            data.port,
            books,
            {str(g["_id"]): g for g in groups},
        ),
        "enforcement": "policy-preview",
        "transport_ready": False,
    }


class Invite(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    role: Literal["admin", "member"] = "member"

    @validator("email")
    def clean_email(cls, value):
        value = value.strip().lower()
        if (
            value.count("@") != 1
            or any(c.isspace() for c in value)
            or "." not in value.split("@")[-1]
        ):
            raise ValueError("Enter a valid email address")
        return value


@router.post("/invitations")
async def invite_member(data: Invite, request: Request):
    user, owner, role = await context(request, True)
    if data.role == "admin" and role != "owner":
        raise HTTPException(403, "Only the owner can invite administrators")
    if (
        await db.workspace_invites.count_documents(
            {
                "user_id": owner,
                "consumed_at": None,
                "revoked_at": None,
                "expires_at": {"$gt": utcnow()},
            }
        )
        >= 100
    ):
        raise HTTPException(
            400, "Revoke an outstanding invitation before creating more"
        )
    token = secrets.token_urlsafe(32)
    invite = {
        "_id": token_digest(token),
        "user_id": owner,
        "email": data.email,
        "role": data.role,
        "created_by": user["_id"],
        "created_at": utcnow(),
        "expires_at": utcnow() + timedelta(days=7),
        "consumed_at": None,
        "revoked_at": None,
    }
    await db.workspace_invites.insert_one(invite)
    return {"token": token, "expires_at": invite["expires_at"]}


@router.delete("/invitations/{invitation_id}")
async def revoke_invitation(invitation_id: str, request: Request):
    _, owner, _ = await context(request, True)
    await db.workspace_invites.update_one(
        {"_id": invitation_id, "user_id": owner, "consumed_at": None},
        {"$set": {"revoked_at": utcnow()}},
    )
    return {"msg": "Invitation revoked"}


class InvitationToken(BaseModel):
    token: str = Field(..., min_length=32, max_length=200)


@router.post("/invitations/preview")
async def preview_invitation(data: InvitationToken):
    invite = await valid_invitation(data.token)
    owner = await db.users.find_one({"_id": invite["user_id"]}, {"name": 1})
    return {
        "email": invite["email"],
        "role": invite["role"],
        "workspace": (owner or {}).get("name", "PortHub"),
        "expires_at": invite["expires_at"],
    }


@router.post("/invitations/accept")
async def accept(data: InvitationToken, request: Request):
    check_origin(request)
    user = await get_authenticated_user(request)
    owner = await accept_invitation(user, data.token)
    return {"workspace_id": owner}


@router.delete("/members/{user_id}")
async def remove_member(user_id: str, request: Request):
    user, owner, role = await context(request, True)
    target = parse_object_id(user_id, "Invalid member")
    if target == owner:
        raise HTTPException(400, "The workspace owner cannot be removed")
    membership = await db.workspace_members.find_one({"_id": f"{owner}:{target}"})
    if membership and membership["role"] == "admin" and role != "owner":
        raise HTTPException(403, "Only the owner can remove administrators")
    if target == user["_id"]:
        raise HTTPException(
            400, "Ask the workspace owner to remove your administrative membership"
        )
    await db.workspace_members.delete_one({"_id": f"{owner}:{target}"})
    await db.machines.update_many(
        {"user_id": owner, "private_owner_id": target},
        {"$set": {"private_owner_revoked": True}},
    )
    await db.machine_groups.update_many(
        {"user_id": owner}, {"$pull": {"user_ids": target}}
    )
    await db.workspace_invites.update_many(
        {"user_id": owner, "created_by": target, "consumed_at": None},
        {"$set": {"revoked_at": utcnow()}},
    )
    return {"msg": "Member removed"}
