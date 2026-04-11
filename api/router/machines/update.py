from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from ..common import (
    get_authenticated_user,
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

    await db.machines.update_one(
        {"_id": machine["_id"]},
        {
            "$set": {
                "name": machine_name,
                "hostname": (data.hostname or "").strip(),
                "is_active": bool(data.is_active),
                "updated_at": utcnow(),
            }
        },
    )

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})

    return {
        "msg": "Machine updated successfully",
        "data": serialize_machine(updated_machine),
    }
