from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.traffic_config import rebuild_traffic_config
from ..common import get_authenticated_user, parse_object_id, utcnow
from .add import _find_conflicting_hosts, _resolve_connection_metadata
from .common import serialize_traffic_route
from .models.traffic_route import TrafficRoute

router = APIRouter()


@router.put("/update")
async def update_traffic_route(data: TrafficRoute, request: Request):
    user = await get_authenticated_user(request)
    route_id = parse_object_id(data.data_id, "Invalid traffic route id")
    route = await db.traffic_routes.find_one({"_id": route_id, "user_id": user["_id"]})
    if not route:
        raise HTTPException(status_code=400, detail="Traffic route not found")

    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Route name is required")

    hosts = data.normalized_hosts()
    conflicting_hosts = await _find_conflicting_hosts(hosts, exclude_route_id=route_id)
    if conflicting_hosts:
        raise HTTPException(
            status_code=400,
            detail=f"Hosts already in use: {', '.join(conflicting_hosts)}",
        )

    await db.traffic_routes.update_one(
        {"_id": route_id},
        {
            "$set": {
                "name": name,
                "description": (data.description or "").strip(),
                "hosts": hosts,
                "target_mode": data.target_mode,
                "target_url": data.normalized_target_url(),
                "entry_points": data.normalized_entry_points(),
                "enabled": True if data.enabled is None else data.enabled,
                "connection": await _resolve_connection_metadata(
                    user_id=user["_id"],
                    connection_data_id=(data.connection_data_id or "").strip() or None,
                ),
                "updated_at": utcnow(),
            }
        },
    )
    updated = await db.traffic_routes.find_one({"_id": route_id})
    await rebuild_traffic_config()
    return {
        "msg": "Traffic route updated successfully",
        "data": serialize_traffic_route(updated),
    }
