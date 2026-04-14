from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.firewall_client import (
    get_stored_connection_firewall_policy,
    is_firewall_configured,
    list_active_ports,
    get_recent_ip_hits,
    get_traffic_snapshot,
    sync_connection_firewall_policy,
)
from ..common import get_authenticated_user, parse_object_id, serialize_connection
from .models.firewall import ConnectionFirewallPolicy, ConnectionTrafficSnapshotRequest

router = APIRouter()


def _is_policy_applied(connection: dict, policy: dict) -> bool:
    return bool(connection.get("enabled", True))


async def _get_user_connection(user: dict, data_id: str) -> dict:
    connection = await db.connections.find_one(
        {
            "_id": parse_object_id(data_id, "Invalid connection id"),
            "user_id": user["_id"],
        }
    )
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    return connection


async def _get_connection_machine(connection: dict) -> dict | None:
    machine_id = connection.get("machine_id")
    if not machine_id:
        return None
    return await db.machines.find_one({"_id": machine_id})


def _require_firewall() -> None:
    if not is_firewall_configured():
        raise HTTPException(status_code=503, detail="Firewall integration is not configured")


@router.get("/firewall/policy/{data_id}")
async def get_connection_firewall_policy(data_id: str, request: Request):
    user = await get_authenticated_user(request)
    connection = await _get_user_connection(user, data_id)
    machine = await _get_connection_machine(connection)

    return {
        "msg": "Connection firewall policy fetched successfully",
        "data": {
            "connection": serialize_connection(connection, machine),
            "firewall": {
                **get_stored_connection_firewall_policy(connection),
                "applied": _is_policy_applied(
                    connection,
                    get_stored_connection_firewall_policy(connection),
                ),
            },
        },
    }


@router.put("/firewall/policy")
async def update_connection_firewall_policy(data: ConnectionFirewallPolicy, request: Request):
    user = await get_authenticated_user(request)
    connection = await _get_user_connection(user, data.data_id)
    updated_policy = {
        "is_public": data.is_public,
        "allowed_ips": [str(ip) for ip in data.allowed_ips],
    }

    await db.connections.update_one(
        {"_id": connection["_id"]},
        {
            "$set": {
                "firewall": updated_policy,
            }
        },
    )
    connection["firewall"] = updated_policy

    await sync_connection_firewall_policy(connection)
    machine = await _get_connection_machine(connection)

    return {
        "msg": "Connection firewall policy updated successfully",
        "data": {
            "connection": serialize_connection(connection, machine),
            "firewall": {
                **updated_policy,
                "applied": _is_policy_applied(connection, updated_policy),
            },
        },
    }


@router.delete("/firewall/policy/{data_id}")
async def delete_connection_firewall_policy(data_id: str, request: Request):
    user = await get_authenticated_user(request)
    connection = await _get_user_connection(user, data_id)
    reset_policy = {
        "is_public": True,
        "allowed_ips": [],
    }

    await db.connections.update_one(
        {"_id": connection["_id"]},
        {
            "$set": {
                "firewall": reset_policy,
            }
        },
    )
    connection["firewall"] = reset_policy

    await sync_connection_firewall_policy(connection)
    machine = await _get_connection_machine(connection)

    return {
        "msg": "Connection firewall policy deleted successfully",
        "data": {
            "connection": serialize_connection(connection, machine),
            "firewall": {
                "is_public": True,
                "allowed_ips": [],
                "applied": bool(connection.get("enabled", True)),
            },
        },
    }


@router.get("/firewall/active")
async def get_user_active_firewall_ports(request: Request):
    _require_firewall()
    user = await get_authenticated_user(request)
    connections = await db.connections.find({"user_id": user["_id"]}).to_list(length=None)
    connections_by_port = {
        connection["external_port"]: connection
        for connection in connections
        if connection.get("external_port") is not None
    }

    machine_ids = list(
        {
            connection["machine_id"]
            for connection in connections
            if connection.get("machine_id") is not None
        }
    )
    machines = await db.machines.find({"_id": {"$in": machine_ids}}).to_list(length=None)
    machines_by_id = {machine["_id"]: machine for machine in machines}

    try:
        active_ports = await list_active_ports()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    filtered = []
    for item in active_ports:
        port = item["port"]
        connection = connections_by_port.get(port)
        if not connection:
            continue
        filtered.append(
            {
                "port": port,
                "last_seen": item["last_seen"],
                "connection": serialize_connection(
                    connection,
                    machines_by_id.get(connection.get("machine_id")),
                ),
            }
        )

    return {
        "msg": "Connection firewall activity fetched successfully",
        "data": filtered,
    }


@router.post("/firewall/traffic/snapshot")
async def get_connection_firewall_traffic(data: ConnectionTrafficSnapshotRequest, request: Request):
    _require_firewall()
    user = await get_authenticated_user(request)

    query = {"user_id": user["_id"]}
    if data.data_ids:
        query["_id"] = {
            "$in": [parse_object_id(data_id, "Invalid connection id") for data_id in data.data_ids]
        }

    connections = await db.connections.find(query).to_list(length=None)
    machine_ids = list(
        {
            connection["machine_id"]
            for connection in connections
            if connection.get("machine_id") is not None
        }
    )
    machines = await db.machines.find({"_id": {"$in": machine_ids}}).to_list(length=None)
    machines_by_id = {machine["_id"]: machine for machine in machines}
    ports = sorted(
        {
            connection["external_port"]
            for connection in connections
            if connection.get("external_port") is not None
        }
    )

    try:
        snapshot = await get_traffic_snapshot(ports)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "msg": "Connection firewall traffic snapshot fetched successfully",
        "data": [
            {
                "connection": serialize_connection(
                    connection,
                    machines_by_id.get(connection.get("machine_id")),
                ),
                "traffic": snapshot.get(str(connection["external_port"]))
                or snapshot.get(connection["external_port"])
                or [],
            }
            for connection in connections
        ],
    }


@router.get("/firewall/recent-ip-hits/{data_id}")
async def get_connection_recent_ip_hits(data_id: str, request: Request, limit: int = 10):
    _require_firewall()
    user = await get_authenticated_user(request)
    connection = await _get_user_connection(user, data_id)

    try:
        recent_hits = await get_recent_ip_hits(connection["external_port"], limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "msg": "Connection recent IP hits fetched successfully",
        "data": recent_hits,
    }
