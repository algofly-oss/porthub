from fastapi import APIRouter, Request
from datetime import datetime, timezone
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
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    data = []
    for route in routes:
        metric = dict(metrics.get(str(route["_id"]), {"requests": 0, "last_requested_at": None}))
        monthly = metric.get("monthly_requests", 0) if metric.get("month") == month else 0
        # Before the first collector batch after an upgrade, the old lifetime
        # counter is safe to reuse only if tracking started this calendar month.
        if "month" not in metric and str((state or {}).get("tracking_since", ""))[:7] == month:
            monthly = metric.get("requests", 0)
        data.append({"route_id": str(route["_id"]), **metric, "monthly_requests": monthly})
    return {"tracking_since": (state or {}).get("tracking_since"), "updated_at": (state or {}).get("updated_at"),
            "month": month, "monthly_tracking_since": (state or {}).get("monthly_tracking_since"),
            "available": state is not None, "coverage_warning": bool((state or {}).get("coverage_warning")), "data": data}
