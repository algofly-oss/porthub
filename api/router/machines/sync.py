from fastapi import APIRouter, HTTPException

from shared.factory import db
from ..common import parse_object_id, serialize_machine, utcnow
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

    return {
        "msg": "Machine synced successfully",
        "data": serialize_machine(updated_machine),
    }
