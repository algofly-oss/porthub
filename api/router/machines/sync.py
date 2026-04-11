from fastapi import APIRouter, HTTPException

from shared.factory import db
from shared.rathole_config import rebuild_server_toml
from shared.sockets import emit_machine_status_changed, set_cached_machine_status
from ..common import is_machine_online, parse_object_id, serialize_machine, utcnow
from .models.machine import MachineSync

router = APIRouter()


@router.post("/sync")
async def sync_machine(data: MachineSync):
    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(data.machine_id, "Invalid machine id"),
            "token": data.token,
        }
    )

    if not machine:
        raise HTTPException(status_code=401, detail="Invalid machine credentials")

    previous_serialized_machine = serialize_machine(machine)
    was_online = is_machine_online(machine)

    await db.machines.update_one(
        {"_id": machine["_id"]},
        {
            "$set": {
                "hostname": (data.hostname or "").strip() or machine.get("hostname", ""),
                "local_ip": (data.local_ip or "").strip(),
                "public_ip": (data.public_ip or "").strip(),
                "is_active": True if data.is_active is None else bool(data.is_active),
                "last_seen_at": utcnow(),
                "updated_at": utcnow(),
            }
        },
    )

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})
    is_online = is_machine_online(updated_machine)
    updated_serialized_machine = serialize_machine(updated_machine)

    set_cached_machine_status(str(updated_machine["_id"]), is_online)

    if (
        was_online != is_online
        or previous_serialized_machine["hostname"]
        != updated_serialized_machine["hostname"]
        or previous_serialized_machine["local_ip"]
        != updated_serialized_machine["local_ip"]
        or previous_serialized_machine["public_ip"]
        != updated_serialized_machine["public_ip"]
    ):
        await emit_machine_status_changed(updated_machine)

    await rebuild_server_toml(allow_empty=True)

    return {
        "msg": "Machine synced successfully",
        "data": updated_serialized_machine,
    }
