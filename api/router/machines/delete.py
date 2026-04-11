import pydantic
from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from ..common import get_authenticated_user, parse_object_id, serialize_machine

router = APIRouter()


class DeleteMachine(pydantic.BaseModel):
    data_id: str


@router.post("/delete")
async def delete_machine(data: DeleteMachine, request: Request):
    user = await get_authenticated_user(request)
    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(data.data_id, "Invalid machine id"),
            "user_id": user["_id"],
        }
    )

    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    await db.connections.delete_many({"machine_id": machine["_id"]})
    await db.machines.delete_one({"_id": machine["_id"]})

    return {
        "msg": "Machine deleted successfully",
        "data": serialize_machine(machine),
    }
