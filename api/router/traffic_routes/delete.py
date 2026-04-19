from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.traffic_config import rebuild_traffic_config
from ..common import get_authenticated_user, parse_object_id
from .common import serialize_traffic_route
from .models.traffic_route import TrafficRouteDelete

router = APIRouter()


@router.post("/delete")
async def delete_traffic_route(data: TrafficRouteDelete, request: Request):
    user = await get_authenticated_user(request)
    route_id = parse_object_id(data.data_id, "Invalid traffic route id")
    route = await db.traffic_routes.find_one({"_id": route_id, "user_id": user["_id"]})
    if not route:
        raise HTTPException(status_code=400, detail="Traffic route not found")

    await db.traffic_routes.delete_one({"_id": route_id})
    await rebuild_traffic_config()
    return {
        "msg": "Traffic route deleted successfully",
        "data": serialize_traffic_route(route),
    }
