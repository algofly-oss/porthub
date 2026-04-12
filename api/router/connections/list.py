from fastapi import APIRouter, Request, HTTPException
from shared.factory import db
from shared.env import (
    EXTERNAL_PORT_RANGE,
    get_external_port_range_error_message,
    is_external_port_allowed,
)
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
    if EXTERNAL_PORT_RANGE is None:
        random_port = random.randint(10000, 65535)
        while await db.connections.find_one({"external_port": random_port}):
            random_port = random.randint(10000, 65535)
    else:
        range_start, range_end = EXTERNAL_PORT_RANGE
        used_ports = set(
            await db.connections.distinct(
                "external_port",
                {"external_port": {"$gte": range_start, "$lte": range_end}},
            )
        )
        available_ports = [
            port for port in range(range_start, range_end + 1) if port not in used_ports
        ]

        if not available_ports:
            raise HTTPException(
                status_code=409,
                detail="No available external ports in the configured range",
            )

        random_port = random.choice(available_ports)

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

    if not is_external_port_allowed(port):
        return {
            "available": False,
            "message": get_external_port_range_error_message(),
        }

    query = {"external_port": port}
    if data_id:
        query["_id"] = {"$ne": parse_object_id(data_id, "Invalid connection id")}

    connection = await db.connections.find_one(query)

    return {
        "available": connection is None,
        "message": None if connection is None else "External port is already assigned",
    }
