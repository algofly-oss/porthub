from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.traffic_config import rebuild_traffic_config
from ..common import get_authenticated_user, parse_object_id, resolve_machine_hostname, utcnow
from .common import serialize_traffic_route
from .models.traffic_route import TrafficRoute

router = APIRouter()


async def _find_conflicting_hosts(hosts: list[str], *, exclude_route_id=None) -> list[str]:
    query = {"hosts": {"$in": hosts}}
    if exclude_route_id is not None:
        query["_id"] = {"$ne": exclude_route_id}

    conflicting_routes = await db.traffic_routes.find(query).to_list(length=None)
    conflicting_hosts: set[str] = set()
    for route in conflicting_routes:
        conflicting_hosts.update(
            host for host in (route.get("hosts") or []) if host in hosts
        )

    return sorted(conflicting_hosts)


async def _resolve_connection_metadata(*, user_id, connection_data_id: str | None) -> dict | None:
    if not connection_data_id:
        return None

    connection = await db.connections.find_one(
        {
            "_id": parse_object_id(connection_data_id, "Invalid connection id"),
            "user_id": user_id,
        }
    )
    if not connection:
        raise HTTPException(status_code=400, detail="Mapped port-pair entry not found")

    machine = None
    machine_id = connection.get("machine_id")
    if machine_id:
        machine = await db.machines.find_one({"_id": machine_id})

    return {
        "data_id": str(connection["_id"]),
        "machine_id": str(machine_id) if machine_id else "",
        "machine_name": machine.get("name", "") if machine else "",
        "machine_hostname": resolve_machine_hostname(machine) if machine else "",
        "service_name": connection.get("service_name", ""),
        "service_description": connection.get("service_description", ""),
        "internal_ip": connection.get("internal_ip", connection.get("internalIp", "0.0.0.0")),
        "internal_port": connection.get("internal_port"),
        "external_port": connection.get("external_port"),
        "enabled": connection.get("enabled", True),
    }


@router.post("/add")
async def add_traffic_route(data: TrafficRoute, request: Request):
    user = await get_authenticated_user(request)
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Route name is required")

    hosts = data.normalized_hosts()
    conflicting_hosts = await _find_conflicting_hosts(hosts)
    if conflicting_hosts:
        raise HTTPException(
            status_code=400,
            detail=f"Hosts already in use: {', '.join(conflicting_hosts)}",
        )

    now = utcnow()
    result = await db.traffic_routes.insert_one(
        {
            "user_id": user["_id"],
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
            "created_at": now,
            "updated_at": now,
        }
    )

    created = await db.traffic_routes.find_one({"_id": result.inserted_id})
    await rebuild_traffic_config()
    return {
        "msg": "Traffic route created successfully",
        "data": serialize_traffic_route(created),
    }
