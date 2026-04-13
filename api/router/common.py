import secrets
import string
from datetime import datetime, timedelta

from bson import ObjectId
from fastapi import HTTPException, Request

from shared.client_release import get_client_version as get_latest_client_version
from shared.factory import db
from shared.env import MACHINE_ONLINE_TTL_SECONDS
from .auth.common import authenticate_user


def get_machine_group_object_ids(machine: dict) -> list[ObjectId]:
    """Effective group memberships (supports legacy single group_id)."""
    raw = machine.get("group_ids")
    if isinstance(raw, list) and raw:
        out: list[ObjectId] = []
        for item in raw:
            oid: ObjectId | None = None
            if isinstance(item, ObjectId):
                oid = item
            elif isinstance(item, str) and ObjectId.is_valid(item):
                oid = ObjectId(item)
            if oid is not None and oid not in out:
                out.append(oid)
        if out:
            return out
    legacy = machine.get("group_id")
    if isinstance(legacy, ObjectId):
        return [legacy]
    if isinstance(legacy, str) and ObjectId.is_valid(legacy):
        return [ObjectId(legacy)]
    return []


def parse_object_id(value: str, detail: str) -> ObjectId:
    if not value or not ObjectId.is_valid(value):
        raise HTTPException(status_code=400, detail=detail)
    return ObjectId(value)


async def get_authenticated_user(request: Request):
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one(
        {"_id": parse_object_id(user_id.decode("utf-8"), "User not logged in")}
    )
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")
    return user


def utcnow():
    return datetime.utcnow()


def resolve_machine_hostname(machine: dict) -> str:
    override = (machine.get("hostname_override") or "").strip()
    if override:
        return override

    client_hostname = (machine.get("client_hostname") or "").strip()
    if client_hostname:
        return client_hostname

    return (machine.get("hostname") or "").strip()


def is_machine_online(machine: dict) -> bool:
    return get_machine_connection_status(machine) in {"online", "auth_required"}


def get_machine_connection_status(machine: dict) -> str:
    if machine.get("enabled", True) is False:
        return "disabled"

    last_seen_at = machine.get("last_seen_at")
    if not isinstance(last_seen_at, datetime):
        return "offline"

    if last_seen_at < utcnow() - timedelta(seconds=MACHINE_ONLINE_TTL_SECONDS):
        return "offline"

    if machine.get("auth_required", False):
        return "auth_required"

    return "online"


async def generate_machine_token() -> str:
    alphabet = string.ascii_letters + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(48))
    while await db.machines.find_one({"token": token}):
        token = "".join(secrets.choice(alphabet) for _ in range(48))
    return token


def serialize_machine(machine: dict):
    connection_status = get_machine_connection_status(machine)
    client_version = (machine.get("client_version") or "").strip()
    latest_client_version = get_latest_client_version()
    client_update_target_version = (machine.get("client_update_target_version") or "").strip()
    client_update_request_id = (machine.get("client_update_request_id") or "").strip()
    client_update_last_handled_request_id = (
        machine.get("client_update_last_handled_request_id") or ""
    ).strip()
    client_update_requested = bool(
        client_update_request_id
        and client_update_request_id != client_update_last_handled_request_id
    )
    group_ids = get_machine_group_object_ids(machine)
    resolved_hostname = resolve_machine_hostname(machine)
    return {
        "_id": str(machine["_id"]),
        "user_id": str(machine["user_id"]),
        "name": machine.get("name", ""),
        "hostname": resolved_hostname,
        "client_hostname": (machine.get("client_hostname") or "").strip(),
        "hostname_override": (machine.get("hostname_override") or "").strip(),
        "group_ids": [str(oid) for oid in group_ids],
        "enabled": machine.get("enabled", True),
        "local_ip": machine.get("local_ip", machine.get("ip_address", "")),
        "public_ip": machine.get("public_ip", ""),
        "token": machine.get("token", ""),
        "is_active": connection_status in {"online", "auth_required"},
        "connection_status": connection_status,
        "auth_required": connection_status == "auth_required",
        "client_version": client_version,
        "latest_client_version": latest_client_version,
        "client_update_available": bool(
            client_version and client_version != latest_client_version
        ),
        "client_update_requested": client_update_requested,
        "client_update_target_version": client_update_target_version,
        "client_update_request_id": client_update_request_id,
        "client_update_requested_at": machine.get("client_update_requested_at"),
        "client_updated_at": machine.get("client_updated_at"),
        "last_seen_at": machine.get("last_seen_at"),
        "created_at": machine.get("created_at"),
        "updated_at": machine.get("updated_at"),
    }


def serialize_connection(connection: dict, machine: dict | None = None):
    machine_id = connection.get("machine_id")
    internal_ip = connection.get("internal_ip", connection.get("internalIp", "0.0.0.0"))
    serialized = {
        "_id": str(connection["_id"]),
        "user_id": str(connection["user_id"]),
        "machine_id": str(machine_id) if machine_id else "",
        "service_name": connection.get("service_name", ""),
        "service_description": connection.get("service_description", ""),
        "internal_ip": internal_ip,
        "internal_port": connection.get("internal_port"),
        "external_port": connection.get("external_port"),
        "enabled": connection.get("enabled", True),
        "created_at": connection.get("created_at"),
        "updated_at": connection.get("updated_at"),
    }

    if machine:
        serialized["machine_name"] = machine.get("name", "")
        serialized["machine_hostname"] = resolve_machine_hostname(machine)
        serialized["machine_local_ip"] = machine.get("local_ip", machine.get("ip_address", ""))
        serialized["machine_public_ip"] = machine.get("public_ip", "")
    else:
        serialized["machine_name"] = connection.get("host_name", "")
        serialized["machine_hostname"] = connection.get("host_id", "")
        serialized["machine_local_ip"] = connection.get("host_ip", "")
        serialized["machine_public_ip"] = ""

    return serialized
