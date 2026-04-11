from fastapi import APIRouter, Request, HTTPException
import pydantic
from shared.factory import db
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

    # This is where a later async broadcast hook can publish Rathole config changes.
    return {
        "msg": "Connection deleted successfully",
        "data": serialize_connection(connection, machine),
    }
