from fastapi import APIRouter, Request, HTTPException
import pydantic
from shared.rathole_config import rebuild_server_toml
from shared.factory import db
from shared.firewall_client import delete_port_policy_best_effort
from shared.sockets import emit_machine_config_changed
from ..common import get_authenticated_user, parse_object_id, serialize_connection

router = APIRouter()

class DeleteConnection(pydantic.BaseModel):
    data_id: str

@router.post("/delete")
async def delete_connection(data: DeleteConnection, request: Request):
    user = await get_authenticated_user(request)

    connection = await db.connections.find_one(
        {
            "_id": parse_object_id(data.data_id, "Invalid connection id"),
            "user_id": user["_id"],
        }
    )
    if not connection:
        raise HTTPException(status_code=400, detail="Connection not found")

    machine = None
    if connection.get("machine_id"):
        machine = await db.machines.find_one({"_id": connection["machine_id"]})
    await db.connections.delete_one({"_id": connection["_id"]})
    await rebuild_server_toml(allow_empty=True)
    if connection.get("external_port"):
        await delete_port_policy_best_effort(connection["external_port"])
    if machine:
        await emit_machine_config_changed(str(machine["_id"]))

    return {
        "msg": "Connection deleted successfully",
        "data": serialize_connection(connection, machine),
    }
