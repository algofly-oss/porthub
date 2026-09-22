from datetime import datetime, timedelta

from fastapi import APIRouter, Query, Request

from shared.factory import db
from ..common import get_authenticated_user, parse_object_id

router = APIRouter()

MAX_HISTORY_DAYS = 366


@router.get("/{machine_id}/status-history")
async def get_machine_status_history(
    machine_id: str,
    request: Request,
    days: int = Query(365, ge=1, le=MAX_HISTORY_DAYS),
):
    user = await get_authenticated_user(request)
    machine_object_id = parse_object_id(machine_id, "Invalid machine id")

    machine = await db.machines.find_one(
        {"_id": machine_object_id, "user_id": user["_id"]}
    )
    if not machine:
        return {"msg": "Machine not found", "data": []}

    since = datetime.utcnow() - timedelta(days=days)
    events = (
        await db.machine_status_events.find(
            {"machine_id": machine_object_id, "changed_at": {"$gte": since}}
        )
        .sort("changed_at", 1)
        .to_list(None)
    )

    return {
        "msg": "Machine status history loaded successfully",
        "data": [
            {"status": event.get("status"), "changed_at": event.get("changed_at")}
            for event in events
        ],
    }
