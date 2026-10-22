"""Opt-in private peer enrollment and authenticated ICE signaling.

All writes are limited to private_* collections. Existing enrollment tokens,
public ports, Rathole configuration and proxies are deliberately untouched.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import re
import secrets
from datetime import timedelta, timezone
from typing import Literal, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from router.common import parse_object_id, utcnow
from shared.access_policy import NetworkPreferences
from shared.factory import db
from shared.private_overlay import (
    FINGERPRINT, HOSTNAME, alias_hostnames, assign_hostnames, compile_grants, hostname_conflict, private_address,
)
from shared.workspaces import token_digest

router = APIRouter(prefix="/private", tags=["Private peers"])
LEASE_SECONDS = 15


RELAY_URL = "turn:relay.porthub.invalid:443?transport=tcp"  # host unused: agents dial the relay WebSocket
RELAY_CREDENTIAL_SECONDS = 12 * 3600


def relay_server(peer_id):
    """Time-limited TURN REST credential for the gateway relay, if enabled."""
    secret = os.environ.get("PORTHUB_RELAY_SECRET", "")
    if len(secret) < 32:
        return None
    username = f"{int(time.time()) + RELAY_CREDENTIAL_SECONDS}:{peer_id}"
    password = base64.b64encode(hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()).decode()
    return {"urls": [RELAY_URL], "username": username, "credential": password}


def ice_servers(peer_id=None):
    """STUN/TURN servers for peer connectivity, from PORTHUB_PRIVATE_ICE_SERVERS.

    JSON list in WebRTC form, e.g. [{"urls": ["stun:stun.example.org:3478"]}].
    Empty means host candidates only (same network). Invalid values are ignored
    rather than breaking private sync for every peer.
    """
    try:
        servers = json.loads(os.environ.get("PORTHUB_PRIVATE_ICE_SERVERS", "[]"))
    except ValueError:
        servers = []
    if not isinstance(servers, list):
        servers = []
    servers = [s for s in servers if isinstance(s, dict) and isinstance(s.get("urls"), list)
               and all(isinstance(u, str) and u.split(":", 1)[0] in {"stun", "turn", "turns"} for u in s["urls"])]
    relay = relay_server(peer_id) if peer_id else None
    return servers + ([relay] if relay else [])


async def browser_context(request, manage=False):
    from router.access import context
    return await context(request, manage)


def custom_hostname(value):
    if value is None or not value.strip():
        return None
    value = value.strip().lower().rstrip(".")
    if not HOSTNAME.fullmatch(value):
        raise ValueError("Use up to 48 letters, numbers or hyphens, not starting or ending with a hyphen")
    return value


class PeerEnrollment(BaseModel):
    machine_id: str
    # Optional custom private name; by default the registered machine name is
    # used (alias is the earlier field name, still accepted).
    hostname: Optional[str] = Field(None, max_length=48)
    alias: Optional[str] = Field(None, max_length=48)

    _hostname = validator("hostname", "alias", allow_reuse=True)(custom_hostname)


class HostnameChange(BaseModel):
    hostname: Optional[str] = Field(None, max_length=48)  # empty/None = machine name

    _hostname = validator("hostname", allow_reuse=True)(custom_hostname)


async def indexes():
    await db.private_peers.create_index([("workspace_id", 1), ("ip", 1)], unique=True)
    # Private names are derived from machine names; only custom names are stored.
    if "workspace_id_1_alias_1" in await db.private_peers.index_information():
        await db.private_peers.drop_index("workspace_id_1_alias_1")
    await db.private_peers.create_index(
        [("workspace_id", 1), ("hostname", 1)], unique=True, name="workspace_custom_hostname",
        partialFilterExpression={"hostname": {"$type": "string"}},
    )
    await db.private_install_tickets.create_index("expires_at", expireAfterSeconds=0)
    await db.private_signals.create_index("expires_at", expireAfterSeconds=0)


@router.post("/peers")
async def enroll_peer(data: PeerEnrollment, request: Request):
    user, owner, role = await browser_context(request)
    machine_id = parse_object_id(data.machine_id, "Invalid machine")
    machine = await db.machines.find_one({"_id": machine_id, "deletion_pending": {"$ne": True}})
    # Members may enroll only their own machines in an invited workspace.
    # Administrators can also enroll existing workspace-owned machines.
    if not machine or not (
        machine["user_id"] == user["_id"] or
        (role in {"owner", "admin"} and machine["user_id"] == owner)
    ):
        raise HTTPException(403, "You cannot enroll this machine")
    if machine.get("enabled", True) is False:
        raise HTTPException(409, "Enable the machine before enrolling private access")
    await indexes()
    peer_id = f"{owner}:{machine_id}"
    existing = await db.private_peers.find_one({"_id": peer_id})
    if existing and existing.get("credential_hash"):
        # Issuing a new installer must not silently invalidate a running client.
        raise HTTPException(409, "This machine already has a private client; revoke it before reinstalling")
    preferences = NetworkPreferences(**(await db.private_networks.find_one({"_id": str(owner)}) or {}))
    custom = data.hostname or data.alias
    if custom:
        machines, peers = await workspace_names(owner)
        clash = hostname_conflict(custom, machine_id, machines, peers)
        if clash:
            raise HTTPException(409, f"{custom} is already used by {clash}")
    for attempt in range(8):
        used = await db.private_peers.find({"workspace_id": owner}, {"ip": 1}).to_list(None)
        try:
            address = existing["ip"] if existing else private_address(preferences.cidr, str(machine_id), {p["ip"] for p in used})
            await db.private_peers.update_one(
                {"_id": peer_id},
                {"$set": {"workspace_id": owner, "machine_id": machine_id,
                          "owner_id": machine["user_id"], "ip": address,
                          "enabled": True, "updated_at": utcnow(), **({"hostname": custom} if custom else {})},
                 "$setOnInsert": {"created_at": utcnow(), "revision": 0}},
                upsert=True,
            )
            break
        except ValueError as error:
            raise HTTPException(409, str(error))
        except DuplicateKeyError:
            if custom and await db.private_peers.find_one({"workspace_id": owner, "hostname": custom, "_id": {"$ne": peer_id}}):
                raise HTTPException(409, "This private hostname is already in use")
            if attempt == 7:
                raise HTTPException(409, "Address allocation changed; retry enrollment")
    ticket = secrets.token_urlsafe(32)
    await db.private_install_tickets.update_many({"peer_id": peer_id, "consumed_at": None}, {"$set": {"consumed_at": utcnow()}})
    await db.private_install_tickets.insert_one({
        "_id": token_digest(ticket), "peer_id": peer_id, "created_by": user["_id"],
        "consumed_at": None, "expires_at": utcnow() + timedelta(minutes=10),
    })
    machines, peers = await workspace_names(owner)
    return {"peer_id": peer_id, "ip": address,
            "hostname": f"{assign_hostnames(machines, peers)[peer_id]}.{preferences.dns_suffix}",
            "ticket": ticket, "expires_in": 600}


async def workspace_names(owner):
    """Machines whose names reserve private hostnames, and the workspace peers.

    Includes every registered workspace machine (enrolled or not) and machines
    of members attached as private peers.
    """
    peers = await db.private_peers.find({"workspace_id": owner}).to_list(None)
    machines = await db.machines.find(
        {"$or": [{"user_id": owner}, {"_id": {"$in": [p["machine_id"] for p in peers]}}],
         "deletion_pending": {"$ne": True}}, {"name": 1, "aliases": 1}).to_list(None)
    return machines, peers


@router.put("/peers/{peer_id}/hostname")
async def rename_peer(peer_id: str, data: HostnameChange, request: Request):
    user, owner, role = await browser_context(request)
    peer = await db.private_peers.find_one({"_id": peer_id, "workspace_id": owner})
    if not peer or (role not in {"owner", "admin"} and peer["owner_id"] != user["_id"]):
        raise HTTPException(404, "Private peer not found")
    await indexes()
    machines, peers = await workspace_names(owner)
    if data.hostname:
        clash = hostname_conflict(data.hostname, peer["machine_id"], machines, peers)
        if clash:
            raise HTTPException(409, f"{data.hostname} is already used by {clash}")
        change = {"$set": {"hostname": data.hostname, "updated_at": utcnow()}}
    else:
        change = {"$unset": {"hostname": ""}, "$set": {"updated_at": utcnow()}}
    try:
        await db.private_peers.update_one({"_id": peer_id}, change)
    except DuplicateKeyError:
        raise HTTPException(409, "This private hostname is already in use")
    machines, peers = await workspace_names(owner)
    return {"hostname": assign_hostnames(machines, peers)[peer_id]}


class Bootstrap(BaseModel):
    ticket: str = Field(..., min_length=32, max_length=200)


@router.post("/bootstrap")
async def bootstrap(data: Bootstrap, response: Response):
    response.headers["Cache-Control"] = "no-store"
    now = utcnow()
    claim = await db.private_install_tickets.find_one_and_update(
        {"_id": token_digest(data.ticket), "consumed_at": None, "expires_at": {"$gt": now}},
        {"$set": {"consumed_at": now}}, return_document=ReturnDocument.AFTER,
    )
    if not claim:
        raise HTTPException(403, "Installer ticket is invalid, expired or already used")
    peer = await db.private_peers.find_one({"_id": claim["peer_id"], "enabled": True})
    if not peer or peer.get("credential_hash"):
        raise HTTPException(403, "Private enrollment is no longer available")
    # Re-check the issuer: a removed member's unconsumed installers are invalid.
    if claim["created_by"] != peer["workspace_id"]:
        membership = await db.workspace_members.find_one({"_id": f"{peer['workspace_id']}:{claim['created_by']}"})
        if not membership or membership.get("role") not in {"admin", "member"}:
            raise HTTPException(403, "Installer issuer no longer belongs to the workspace")
    credential = secrets.token_urlsafe(32)
    result = await db.private_peers.update_one(
        {"_id": peer["_id"], "enabled": True, "credential_hash": {"$exists": False}},
        {"$set": {"credential_hash": token_digest(credential), "credential_created_at": now}},
    )
    if result.modified_count != 1:
        raise HTTPException(409, "Enrollment was already completed")
    return {"peer_id": peer["_id"], "token": credential, "workspace": str(peer["workspace_id"])}


class PeerChange(BaseModel):
    enabled: bool


@router.put("/peers/{peer_id}")
async def change_peer(peer_id: str, data: PeerChange, request: Request):
    _, owner, _ = await browser_context(request, True)
    result = await db.private_peers.update_one(
        {"_id": peer_id, "workspace_id": owner},
        {"$set": {"enabled": data.enabled, "updated_at": utcnow()}},
    )
    if not result.matched_count:
        raise HTTPException(404, "Private peer not found")
    return {"msg": "Private access enabled" if data.enabled else "Private access disabled"}


@router.delete("/peers/{peer_id}")
async def revoke_peer(peer_id: str, request: Request):
    user, owner, role = await browser_context(request)
    peer = await db.private_peers.find_one({"_id": peer_id, "workspace_id": owner})
    if not peer or (role not in {"owner", "admin"} and peer["owner_id"] != user["_id"]):
        raise HTTPException(404, "Private peer not found")
    await db.private_peers.update_one({"_id": peer_id}, {"$set": {"enabled": False}, "$unset": {"credential_hash": "", "fingerprint": "", "instance": ""}})
    await db.private_install_tickets.update_many({"peer_id": peer_id}, {"$set": {"consumed_at": utcnow()}})
    await db.private_signals.delete_many({"$or": [{"from": peer_id}, {"to": peer_id}]})
    return {"msg": "Private credential revoked; public access is unchanged"}


class Description(BaseModel):
    type: Literal["offer", "answer"]
    sdp: str = Field(..., min_length=1, max_length=65536)


class Signal(BaseModel):
    to: str = Field(..., min_length=1, max_length=60)
    session: str = Field(..., regex=r"^[a-zA-Z0-9-]{16,64}$")
    description: Description


class ClientSync(BaseModel):
    peer_id: str = Field(..., max_length=60)
    token: str = Field(..., min_length=32, max_length=200)
    fingerprint: str = Field(..., min_length=95, max_length=95)
    instance: str = Field(..., regex=r"^[a-zA-Z0-9-]{16,64}$")
    signals: list[Signal] = Field(default_factory=list, max_items=16)
    acks: list[str] = Field(default_factory=list, max_items=128)
    paths: dict[str, Literal["direct", "relay", "connecting"]] = Field(default_factory=dict)

    @validator("fingerprint")
    def fingerprint_format(cls, value):
        if not FINGERPRINT.fullmatch(value):
            raise ValueError("A SHA-256 certificate fingerprint is required")
        return value.upper()


async def active_inventory(owner):
    peers = await db.private_peers.find({"workspace_id": owner, "enabled": True}).to_list(None)
    machines = await db.machines.find({"_id": {"$in": [p["machine_id"] for p in peers]}, "enabled": {"$ne": False}, "deletion_pending": {"$ne": True}, "private_owner_revoked": {"$ne": True}}).to_list(None)
    members = await db.workspace_members.find({"workspace_id": owner, "role": {"$in": ["member", "admin"]}}).to_list(None)
    valid_owners = {owner, *[m["user_id"] for m in members]}
    machines_by_id = {m["_id"]: m for m in machines}
    peers = [p for p in peers if p["machine_id"] in machines_by_id and p["owner_id"] in valid_owners]
    return peers, machines_by_id


@router.post("/sync")
async def sync(data: ClientSync, response: Response):
    response.headers["Cache-Control"] = "no-store"
    peer = await db.private_peers.find_one({"_id": data.peer_id, "credential_hash": token_digest(data.token), "enabled": True})
    if not peer:
        raise HTTPException(403, "Private credential invalid or revoked")
    owner = peer["workspace_id"]
    peers, inventory = await active_inventory(owner)
    if data.peer_id not in {p["_id"] for p in peers}:
        raise HTTPException(403, "Machine or workspace membership is disabled")
    if len(data.paths) > 1000:
        raise HTTPException(400, "Too many path reports")
    now = utcnow()
    updated = await db.private_peers.find_one_and_update(
        {"_id": peer["_id"], "enabled": True, "credential_hash": peer["credential_hash"]},
        {"$set": {"fingerprint": data.fingerprint, "instance": data.instance, "last_seen_at": now, "paths": data.paths}, "$inc": {"revision": 1}},
        return_document=ReturnDocument.AFTER,
    )
    if not updated:
        raise HTTPException(403, "Private credential revoked")
    peers = [updated if p["_id"] == updated["_id"] else p for p in peers]
    groups_list = await db.machine_groups.find({"user_id": owner}).to_list(None)
    groups = {str(g["_id"]): g for g in groups_list}
    machines = [{**inventory[p["machine_id"]], "user_id": owner, "private_owner_id": p["owner_id"]} for p in peers]
    books = await db.access_rulebooks.find({"user_id": owner}).to_list(None)
    raw_grants = compile_grants(machines, books, groups)
    mapping = {str(p["machine_id"]): p["_id"] for p in peers}
    grants = [{**g, "source": mapping[g["source"]], "destination": mapping[g["destination"]]} for g in raw_grants if data.peer_id in {mapping[g["source"]], mapping[g["destination"]]}]
    reachable = {data.peer_id}
    for grant in grants:
        reachable.update([grant["source"], grant["destination"]])
    peer_by_id = {p["_id"]: p for p in peers if p["_id"] in reachable}
    for message in data.signals:
        target = peer_by_id.get(message.to)
        if not target or target["_id"] == data.peer_id or not target.get("fingerprint"):
            continue
        expected_offer = data.peer_id < message.to
        if (message.description.type == "offer") != expected_offer:
            raise HTTPException(400, "Invalid peer negotiation direction")
        fingerprints = re.findall(r"(?m)^a=fingerprint:sha-256 ([^\r\n]+)", message.description.sdp)
        if not fingerprints or any(value.upper() != data.fingerprint for value in fingerprints):
            raise HTTPException(400, "Signaling certificate does not match the enrolled client")
        signal_id = token_digest(f"{data.peer_id}:{data.instance}:{message.to}:{message.session}:{message.description.type}")
        await db.private_signals.update_one({"_id": signal_id}, {"$setOnInsert": {
            "from": data.peer_id, "to": message.to, "source_instance": data.instance,
            "target_instance": target.get("instance"), "session": message.session,
            "fingerprint": data.fingerprint, "description": message.description.dict(),
            "expires_at": now + timedelta(seconds=45),
        }}, upsert=True)
    if data.acks:
        await db.private_signals.delete_many({"_id": {"$in": data.acks}, "to": data.peer_id})
    incoming = await db.private_signals.find({"to": data.peer_id, "target_instance": data.instance, "from": {"$in": list(reachable)}, "expires_at": {"$gt": now}}).limit(128).to_list(None)
    # Filter messages invalidated by the source's restart/certificate rotation.
    incoming = [s for s in incoming if s["from"] in peer_by_id and s["source_instance"] == peer_by_id[s["from"]].get("instance") and s["fingerprint"] == peer_by_id[s["from"]].get("fingerprint")]
    preferences = NetworkPreferences(**(await db.private_networks.find_one({"_id": str(owner)}) or {}))
    all_machines, all_peers = await workspace_names(owner)
    labels = assign_hostnames(all_machines, all_peers)
    alias_labels = alias_hostnames(all_machines, all_peers, labels)
    return {"snapshot": {
        "workspace": str(owner), "self": data.peer_id, "revision": updated["revision"],
        "expires_at": (now + timedelta(seconds=LEASE_SECONDS)).replace(tzinfo=timezone.utc),
        "peers": [{"id": p["_id"], "ip": p["ip"], "fingerprint": p.get("fingerprint", ""),
                   "instance": p.get("instance", ""), "hostname": f"{labels[p['_id']]}.{preferences.dns_suffix}",
                   "aliases": [f"{a}.{preferences.dns_suffix}" for a in alias_labels.get(p["_id"], [])]} for p in peer_by_id.values()],
        "grants": grants,
    }, "signals": [{"id": s["_id"], "from": s["from"], "session": s["session"], "description": s["description"]} for s in incoming],
        "ice_servers": ice_servers(data.peer_id), "poll_seconds": 1}
