from fastapi import APIRouter, Request
from shared.factory import db
from shared.proxy_activity import STATE_ID
from ..common import get_authenticated_user

router = APIRouter()


@router.get("/activity")
async def proxy_activity(request: Request):
    user = await get_authenticated_user(request)
    routes = await db.traffic_routes.find({"user_id": user["_id"]}, {"_id": 1, "hosts": 1}).to_list(None)
    state = await db.proxy_activity.find_one({"_id": STATE_ID})
    metrics = (state or {}).get("metrics", {})
    return {"tracking_since": (state or {}).get("tracking_since"), "updated_at": (state or {}).get("updated_at"),
            "available": state is not None, "coverage_warning": bool((state or {}).get("coverage_warning")), "data": [{"route_id": str(route["_id"]),
                **metrics.get(str(route["_id"]), {"requests": 0, "last_requested_at": None})} for route in routes]}
