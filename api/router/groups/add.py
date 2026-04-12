from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from ..common import get_authenticated_user, utcnow
from .common import serialize_machine_group
from .models.group import MachineGroupCreate

router = APIRouter()


@router.post("/add")
async def add_machine_group(data: MachineGroupCreate, request: Request):
    user = await get_authenticated_user(request)
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required")

    existing_count = await db.machine_groups.count_documents({"user_id": user["_id"]})
    now = utcnow()
    result = await db.machine_groups.insert_one(
        {
            "user_id": user["_id"],
            "name": name,
            "sort_order": existing_count,
            "created_at": now,
            "updated_at": now,
        }
    )
    created = await db.machine_groups.find_one({"_id": result.inserted_id})
    return {
        "msg": "Group created successfully",
        "data": serialize_machine_group(created),
    }
