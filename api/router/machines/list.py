from fastapi import APIRouter, Request

from shared.factory import db
from ..common import get_authenticated_user, serialize_machine

router = APIRouter()


@router.get("/list")
async def list_machines(request: Request):
    user = await get_authenticated_user(request)
    machines = (
        await db.machines.find({"user_id": user["_id"]}).sort("created_at", 1).to_list(None)
    )

    return {
        "msg": "Machines listed successfully",
        "data": [serialize_machine(machine) for machine in machines],
    }
