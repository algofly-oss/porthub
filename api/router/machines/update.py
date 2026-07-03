from fastapi import APIRouter, HTTPException, Request
from urllib.parse import urlsplit

from shared.factory import db
from shared.firewall_client import sync_machine_connection_firewall_policies
from shared.rathole_config import rebuild_server_toml
from shared.sockets import (
    emit_machine_config_changed,
    emit_machine_status_changed,
    set_cached_machine_status,
)
from ..common import (
    get_authenticated_user,
    is_machine_online,
    parse_object_id,
    resolve_machine_hostname,
    serialize_machine,
    utcnow,
)
from .models.machine import Machine

router = APIRouter()


def _clean_optional_text(value: str | None, field_label: str, *, max_length: int = 255) -> str:
    cleaned = (value or "").strip()
    if len(cleaned) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"{field_label} must be {max_length} characters or fewer",
        )
    return cleaned


def _clean_public_base_url(value: str | None) -> str:
    cleaned = _clean_optional_text(value, "PortHub public base URL", max_length=512)
    if not cleaned:
        return ""

    parsed = urlsplit(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="PortHub public base URL must be an http(s) URL",
        )
    return cleaned.rstrip("/")


def _sorted_group_id_tuple(serialized: dict) -> tuple[str, ...]:
    ids = serialized.get("group_ids") or []
    if not isinstance(ids, list):
        return tuple()
    return tuple(sorted(str(x) for x in ids if x))


@router.put("/update")
async def update_machine(data: Machine, request: Request):
    user = await get_authenticated_user(request)
    machine_id = parse_object_id(data.data_id, "Invalid machine id")
    machine_name = data.name.strip()
    if not machine_name:
        raise HTTPException(status_code=400, detail="Machine name is required")

    machine = await db.machines.find_one({"_id": machine_id, "user_id": user["_id"]})

    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    previous_serialized_machine = serialize_machine(machine)
    previous_effective_hostname = resolve_machine_hostname(machine)
    was_online = is_machine_online(machine)
    next_enabled = (
        bool(data.enabled)
        if data.enabled is not None
        else (
            bool(data.is_active)
            if data.is_active is not None
            else machine.get("enabled", True)
        )
    )

    incoming = data.dict(exclude_unset=True)
    next_hostname_override = (data.hostname or "").strip()
    next_client_hostname = (machine.get("client_hostname") or "").strip()
    next_effective_hostname = (
        next_hostname_override
        or next_client_hostname
        or (machine.get("hostname") or "").strip()
    )
    mongo_set = {
        "name": machine_name,
        "hostname": next_effective_hostname,
        "hostname_override": next_hostname_override,
        "enabled": next_enabled,
        "updated_at": utcnow(),
    }
    mongo_unset: list[str] = []

    if "group_ids" in incoming:
        raw_list = incoming["group_ids"]
        if raw_list is None:
            raw_list = []
        if not isinstance(raw_list, list):
            raise HTTPException(status_code=400, detail="group_ids must be a list")
        validated: list = []
        for item in raw_list:
            if item is None or (isinstance(item, str) and not str(item).strip()):
                continue
            oid = parse_object_id(str(item).strip(), "Invalid group id")
            grp = await db.machine_groups.find_one({"_id": oid, "user_id": user["_id"]})
            if not grp:
                raise HTTPException(status_code=400, detail="Group not found")
            if oid not in validated:
                validated.append(oid)
        mongo_set["group_ids"] = validated
        mongo_unset.append("group_id")

    if "client_setup_public_base_url" in incoming:
        mongo_set["client_setup_public_base_url"] = _clean_public_base_url(
            data.client_setup_public_base_url
        )

    if "client_setup_rathole_server_address" in incoming:
        mongo_set["client_setup_rathole_server_address"] = _clean_optional_text(
            data.client_setup_rathole_server_address,
            "Rathole server address",
        )

    if "client_setup_service_domain" in incoming:
        mongo_set["client_setup_service_domain"] = _clean_optional_text(
            data.client_setup_service_domain,
            "Service domain",
        )

    update_doc: dict = {"$set": mongo_set}
    if mongo_unset:
        update_doc["$unset"] = {field: "" for field in mongo_unset}

    await db.machines.update_one({"_id": machine["_id"]}, update_doc)

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})
    updated_serialized_machine = serialize_machine(updated_machine)
    updated_effective_hostname = resolve_machine_hostname(updated_machine)
    is_online = is_machine_online(updated_machine)

    set_cached_machine_status(str(updated_machine["_id"]), is_online)

    rathole_fields_changed = (
        previous_serialized_machine["name"] != updated_serialized_machine["name"]
        or previous_effective_hostname != updated_effective_hostname
        or previous_serialized_machine.get("enabled", True)
        != updated_serialized_machine.get("enabled", True)
        or previous_serialized_machine.get("client_setup_rathole_server_address", "")
        != updated_serialized_machine.get("client_setup_rathole_server_address", "")
    )

    prev_groups = _sorted_group_id_tuple(previous_serialized_machine)
    next_groups = _sorted_group_id_tuple(updated_serialized_machine)
    group_changed = prev_groups != next_groups

    if (
        was_online != is_online
        or previous_serialized_machine["name"] != updated_serialized_machine["name"]
        or previous_effective_hostname != updated_effective_hostname
        or previous_serialized_machine.get("enabled", True)
        != updated_serialized_machine.get("enabled", True)
        or group_changed
    ):
        await emit_machine_status_changed(updated_machine)

    if rathole_fields_changed:
        await rebuild_server_toml(allow_empty=True)
        await emit_machine_config_changed(str(updated_machine["_id"]))

    if previous_serialized_machine.get("enabled", True) != updated_serialized_machine.get(
        "enabled", True
    ):
        await sync_machine_connection_firewall_policies(updated_machine["_id"])

    return {
        "msg": "Machine updated successfully",
        "data": updated_serialized_machine,
    }
