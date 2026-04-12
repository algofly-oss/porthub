from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from ..common import get_authenticated_user, parse_object_id, utcnow
from .common import serialize_machine_group
from .models.group import MachineGroupDelete

router = APIRouter()


@router.post("/delete")
async def delete_machine_group(data: MachineGroupDelete, request: Request):
    user = await get_authenticated_user(request)
    group_id = parse_object_id(data.data_id, "Invalid group id")
    group = await db.machine_groups.find_one({"_id": group_id, "user_id": user["_id"]})
    if not group:
        raise HTTPException(status_code=400, detail="Group not found")

    now = utcnow()
    await db.machines.update_many(
        {"user_id": user["_id"], "group_ids": group_id},
        {"$pull": {"group_ids": group_id}, "$set": {"updated_at": now}},
    )
    await db.machines.update_many(
        {"user_id": user["_id"], "group_id": group_id},
        {"$unset": {"group_id": ""}, "$set": {"updated_at": now}},
    )
    await db.machine_groups.delete_one({"_id": group_id})
    return {
        "msg": "Group deleted successfully",
        "data": serialize_machine_group(group),
    }
