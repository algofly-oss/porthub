from fastapi import APIRouter, Request

from shared.factory import db
from ..common import get_authenticated_user
from .common import serialize_machine_group

router = APIRouter()


@router.get("/list")
async def list_machine_groups(request: Request):
    user = await get_authenticated_user(request)
    groups = (
        await db.machine_groups.find({"user_id": user["_id"]})
        .sort([("sort_order", 1), ("created_at", 1)])
        .to_list(length=None)
    )
    return {
        "msg": "Groups listed successfully",
        "data": [serialize_machine_group(g) for g in groups],
    }
