from fastapi import APIRouter, Request, HTTPException
from shared.env import get_external_port_range_error_message, is_external_port_allowed
from shared.rathole_config import rebuild_server_toml
from shared.factory import db
from shared.firewall_client import delete_port_policy_best_effort, sync_connection_firewall_policy
from shared.sockets import emit_machine_config_changed
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

    if not is_external_port_allowed(data.external_port):
        raise HTTPException(
            status_code=400,
            detail=get_external_port_range_error_message(),
        )

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
                "internal_ip": data.internal_ip,
                "internal_port": data.internal_port,
                "external_port": data.external_port,
                "enabled": True if data.enabled is None else data.enabled,
                "updated_at": utcnow(),
            }
        },
    )

    res = await db.connections.find_one({"_id": connection["_id"]})
    await rebuild_server_toml(allow_empty=True)
    await emit_machine_config_changed(str(machine["_id"]))
    previous_machine_id = connection.get("machine_id")
    if previous_machine_id and previous_machine_id != machine["_id"]:
        await emit_machine_config_changed(str(previous_machine_id))
    previous_external_port = connection.get("external_port")
    if previous_external_port and previous_external_port != data.external_port:
        await delete_port_policy_best_effort(previous_external_port)
    res = await db.connections.find_one({"_id": connection["_id"]})
    await sync_connection_firewall_policy(res)

    return {
        "msg": "Connection updated successfully",
        "data": serialize_connection(res, machine),
    }
