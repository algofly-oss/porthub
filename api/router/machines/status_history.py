from datetime import datetime, timedelta

from fastapi import APIRouter, Query, Request

from shared.factory import db
from ..common import get_authenticated_user, is_machine_online, parse_object_id

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
    # The last change before the window tells us the state the window opens in.
    previous_event = await db.machine_status_events.find_one(
        {"machine_id": machine_object_id, "changed_at": {"$lt": since}},
        sort=[("changed_at", -1)],
    )
    if previous_event:
        events.insert(0, {**previous_event, "changed_at": since})

    return {
        "msg": "Machine status history loaded successfully",
        "data": [
            {"status": event.get("status"), "changed_at": event.get("changed_at")}
            for event in events
        ],
        "current_status": "online" if is_machine_online(machine) else "offline",
    }
