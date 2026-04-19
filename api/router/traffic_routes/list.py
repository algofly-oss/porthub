from fastapi import APIRouter, Request

from shared.factory import db
from ..common import get_authenticated_user
from .common import serialize_traffic_route

router = APIRouter()


@router.get("/list")
async def list_traffic_routes(request: Request):
    user = await get_authenticated_user(request)
    routes = (
        await db.traffic_routes.find({"user_id": user["_id"]})
        .sort([("created_at", 1), ("_id", 1)])
        .to_list(length=None)
    )
    return {
        "msg": "Traffic routes listed successfully",
        "data": [serialize_traffic_route(route) for route in routes],
    }
