from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from shared.connection_refresh import refresh_connection_config
from shared.factory import db
from ..common import get_authenticated_user, parse_object_id, serialize_connection

router = APIRouter()


class RefreshConnection(BaseModel):
    data_id: str


@router.post("/refresh")
async def refresh_connection(data: RefreshConnection, request: Request):
    user = await get_authenticated_user(request)
    connection = await db.connections.find_one(
        {
            "_id": parse_object_id(data.data_id, "Invalid connection id"),
            "user_id": user["_id"],
        }
    )
    if not connection:
        raise HTTPException(status_code=400, detail="Connection not found")

    if connection.get("enabled", True) is False:
        raise HTTPException(status_code=400, detail="Enable the service before refreshing")

    refreshed_connection = await refresh_connection_config(connection, force=True)
    if not refreshed_connection:
        raise HTTPException(status_code=400, detail="Could not refresh connection")

    machine = None
    if refreshed_connection.get("machine_id"):
        machine = await db.machines.find_one({"_id": refreshed_connection["machine_id"]})

    return {
        "msg": "Connection refreshed successfully",
        "data": serialize_connection(refreshed_connection, machine),
    }
