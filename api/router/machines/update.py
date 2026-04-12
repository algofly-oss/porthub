from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
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
    serialize_machine,
    utcnow,
)
from .models.machine import Machine

router = APIRouter()


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

    await db.machines.update_one(
        {"_id": machine["_id"]},
        {
            "$set": {
                "name": machine_name,
                "hostname": (data.hostname or "").strip(),
                "enabled": next_enabled,
                "updated_at": utcnow(),
            }
        },
    )

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})
    updated_serialized_machine = serialize_machine(updated_machine)
    is_online = is_machine_online(updated_machine)

    set_cached_machine_status(str(updated_machine["_id"]), is_online)

    if (
        was_online != is_online
        or previous_serialized_machine["name"] != updated_serialized_machine["name"]
        or previous_serialized_machine["hostname"]
        != updated_serialized_machine["hostname"]
        or previous_serialized_machine.get("enabled", True)
        != updated_serialized_machine.get("enabled", True)
    ):
        await emit_machine_status_changed(updated_machine)

    await rebuild_server_toml(allow_empty=True)
    await emit_machine_config_changed(str(updated_machine["_id"]))

    return {
        "msg": "Machine updated successfully",
        "data": updated_serialized_machine,
    }
