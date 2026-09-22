from fastapi import APIRouter, Depends

from shared.factory import db
from ..common import serialize_connection, serialize_machine
from .common import require_admin_user

router = APIRouter()


@router.get("/overview")
async def get_platform_overview(admin_user: dict = Depends(require_admin_user)):
    users = await db.users.find({}).sort("created_at", 1).to_list(None)
    machines = await db.machines.find({"deletion_pending": {"$ne": True}}).to_list(None)
    connections = await db.connections.find({}).to_list(None)

    machines_by_id: dict[str, dict] = {str(machine["_id"]): machine for machine in machines}
    machines_by_user_id: dict[str, list[dict]] = {}
    for machine in machines:
        machines_by_user_id.setdefault(str(machine["user_id"]), []).append(machine)

    connections_by_machine_id: dict[str, list[dict]] = {}
    for connection in connections:
        machine_id = connection.get("machine_id")
        if not machine_id:
            continue
        key = str(machine_id)
        connections_by_machine_id.setdefault(key, []).append(connection)

    def _serialize_machine_with_ports(machine: dict) -> dict:
        machine_id = str(machine["_id"])
        machine_connections = sorted(
            connections_by_machine_id.get(machine_id, []),
            key=lambda connection: connection.get("external_port") or 0,
        )
        return {
            **serialize_machine(machine),
            "num_ports": len(machine_connections),
            "ports": [
                serialize_connection(connection, machines_by_id.get(machine_id))
                for connection in machine_connections
            ],
        }

    overview = []
    for user in users:
        user_id = str(user["_id"])
        user_machines = machines_by_user_id.get(user_id, [])
        overview.append(
            {
                "user": {
                    "id": user_id,
                    "name": user.get("name", ""),
                    "email": user.get("email") or user.get("username", ""),
                    "role": user.get("role", "user"),
                    "created_at": user.get("created_at"),
                },
                "machines": [
                    _serialize_machine_with_ports(machine) for machine in user_machines
                ],
            }
        )

    return {"msg": "Platform overview loaded successfully", "data": overview}
