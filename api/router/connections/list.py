from fastapi import APIRouter, Request, HTTPException
from shared.factory import db
from ..common import (
    get_authenticated_user,
    parse_object_id,
    serialize_connection,
)
import random

router = APIRouter()


@router.get("/list")
async def list_connections(request: Request):
    user = await get_authenticated_user(request)
    data = await db.connections.find({"user_id": user["_id"]}).to_list(length=None)
    machine_ids = list({connection["machine_id"] for connection in data if connection.get("machine_id")})
    machines = await db.machines.find({"_id": {"$in": machine_ids}}).to_list(length=None)
    machines_by_id = {machine["_id"]: machine for machine in machines}

    return {
        "msg": "Connections listed successfully",
        "data": [
            serialize_connection(connection, machines_by_id.get(connection.get("machine_id")))
            for connection in data
        ],
    }


@router.get("/random")
async def get_random_port(request: Request):
    random_port = random.randint(10000, 65535)
    while await db.connections.find_one({"external_port": random_port}):
        random_port = random.randint(10000, 65535)

    return {
        "port": random_port
    }


@router.get("/external-port/{port}/availability")
async def external_port_availability(
    port: int,
    request: Request,
    data_id: str | None = None,
):
    await get_authenticated_user(request)

    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port")

    query = {"external_port": port}
    if data_id:
        query["_id"] = {"$ne": parse_object_id(data_id, "Invalid connection id")}

    connection = await db.connections.find_one(query)

    return {
        "available": connection is None,
        "message": None if connection is None else "External port is already assigned",
    }
