from fastapi import APIRouter, Request, HTTPException
from shared.env import get_external_port_range_error_message, is_external_port_allowed
from shared.rathole_config import rebuild_server_toml
from shared.factory import db
from shared.sockets import emit_machine_config_changed
from ..common import (
    get_authenticated_user,
    parse_object_id,
    serialize_connection,
    utcnow,
)
from .models.connection import Connection


router = APIRouter()

@router.post("/add")
async def add_connection(data: Connection, request: Request):
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

    if not is_external_port_allowed(data.external_port):
        raise HTTPException(
            status_code=400,
            detail=get_external_port_range_error_message(),
        )

    connection = await db.connections.find_one({"external_port": data.external_port})
    if connection:
        raise HTTPException(status_code=400, detail="Port already in use")

    now = utcnow()
    result = await db.connections.insert_one(
        {
            "user_id": user["_id"],
            "machine_id": machine["_id"],
            "service_name": service_name,
            "service_description": (data.service_description or "").strip(),
            "internal_ip": data.internal_ip,
            "internal_port": data.internal_port,
            "external_port": data.external_port,
            "enabled": True if data.enabled is None else data.enabled,
            "created_at": now,
            "updated_at": now,
        }
    )

    res = await db.connections.find_one({"_id": result.inserted_id})
    await rebuild_server_toml(allow_empty=True)
    await emit_machine_config_changed(str(machine["_id"]))

    return {
        "msg": "Connection added successfully",
        "data": serialize_connection(res, machine),
    }
