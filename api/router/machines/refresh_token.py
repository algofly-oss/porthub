import pydantic
from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.rathole_config import rebuild_server_toml
from ..common import (
    generate_machine_token,
    get_authenticated_user,
    parse_object_id,
    serialize_machine,
    utcnow,
)

router = APIRouter()


class RefreshMachineToken(pydantic.BaseModel):
    data_id: str


@router.post("/refresh-token")
async def refresh_machine_token(data: RefreshMachineToken, request: Request):
    user = await get_authenticated_user(request)
    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(data.data_id, "Invalid machine id"),
            "user_id": user["_id"],
        }
    )

    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    new_token = await generate_machine_token()
    await db.machines.update_one(
        {"_id": machine["_id"]},
        {
            "$set": {
                "token": new_token,
                "updated_at": utcnow(),
            }
        },
    )

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})
    await rebuild_server_toml(allow_empty=True)

    return {
        "msg": "Machine token refreshed successfully",
        "data": serialize_machine(updated_machine),
    }
