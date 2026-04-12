import pydantic
import secrets
from fastapi import APIRouter, HTTPException, Request

from shared.client_release import get_client_version as get_latest_client_version
from shared.factory import db
from shared.sockets import emit_machine_status_changed
from ..common import get_authenticated_user, parse_object_id, serialize_machine, utcnow

router = APIRouter()


class RequestMachineClientUpdate(pydantic.BaseModel):
    data_id: str


@router.post("/request-client-update")
async def request_machine_client_update(
    data: RequestMachineClientUpdate,
    request: Request,
):
    user = await get_authenticated_user(request)
    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(data.data_id, "Invalid machine id"),
            "user_id": user["_id"],
        }
    )

    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    now = utcnow()
    latest_client_version = get_latest_client_version()

    await db.machines.update_one(
        {"_id": machine["_id"]},
        {
            "$set": {
                "client_update_target_version": latest_client_version,
                "client_update_request_id": secrets.token_hex(8),
                "client_update_requested_at": now,
                "updated_at": now,
            }
        },
    )

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})
    await emit_machine_status_changed(updated_machine)

    return {
        "msg": "Machine client update requested successfully",
        "data": serialize_machine(updated_machine),
    }
