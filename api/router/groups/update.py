from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from ..common import get_authenticated_user, parse_object_id, utcnow
from .common import serialize_machine_group
from .models.group import MachineGroupUpdate

router = APIRouter()


@router.put("/update")
async def update_machine_group(data: MachineGroupUpdate, request: Request):
    user = await get_authenticated_user(request)
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required")

    group_id = parse_object_id(data.data_id, "Invalid group id")
    group = await db.machine_groups.find_one({"_id": group_id, "user_id": user["_id"]})
    if not group:
        raise HTTPException(status_code=400, detail="Group not found")

    await db.machine_groups.update_one(
        {"_id": group_id},
        {"$set": {"name": name, "updated_at": utcnow()}},
    )
    updated = await db.machine_groups.find_one({"_id": group_id})
    return {
        "msg": "Group updated successfully",
        "data": serialize_machine_group(updated),
    }
