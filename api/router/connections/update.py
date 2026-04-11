from fastapi import APIRouter, Request, HTTPException
from shared.factory import db
from ..common import (
    get_authenticated_user,
    parse_object_id,
    serialize_connection,
    utcnow,
)
from .models.connection import Connection

router = APIRouter()

@router.put("/update")
async def update_connection(data: Connection, request: Request):
    user = await get_authenticated_user(request)
    service_name = data.service_name.strip()
    if not service_name:
        raise HTTPException(status_code=400, detail="Service name is required")

    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(data.machine_id, "Invalid machine id"),
            "user_id": user["_id"],
        }
    )
    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    connection = await db.connections.find_one(
        {
            "_id": parse_object_id(data.data_id, "Invalid connection id"),
            "user_id": user["_id"],
        }
    )
    if not connection:
        raise HTTPException(status_code=400, detail="Connection not found")

    existing_port = await db.connections.find_one({
        "external_port": data.external_port,
        "_id": {"$ne": connection["_id"]},
    })
    if existing_port:
        raise HTTPException(status_code=400, detail="Port already in use")

    await db.connections.update_one(
        {"_id": connection["_id"]},
        {
            "$set": {
                "machine_id": machine["_id"],
                "service_name": service_name,
                "service_description": (data.service_description or "").strip(),
                "internal_port": data.internal_port,
                "external_port": data.external_port,
                "enabled": True if data.enabled is None else data.enabled,
                "updated_at": utcnow(),
            }
        },
    )

    # This is where a later async broadcast hook can publish Rathole config changes.
    res = await db.connections.find_one({"_id": connection["_id"]})

    return {
        "msg": "Connection updated successfully",
        "data": serialize_connection(res, machine),
    }
