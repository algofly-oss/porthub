from fastapi import APIRouter, HTTPException, Request, Response

from shared.factory import db
from shared.machine_client import (
    build_machine_config_bundle,
    build_machine_endpoints,
    sync_machine_runtime,
)
from shared.sockets import emit_machine_status_changed, set_cached_machine_status
from ..common import is_machine_online, parse_object_id, serialize_machine
from .models.machine import MachineSync

router = APIRouter()


@router.post("/sync")
async def sync_machine(data: MachineSync, request: Request, response: Response):
    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(data.machine_id, "Invalid machine id"),
            "token": data.token,
        }
    )

    if not machine:
        raise HTTPException(status_code=401, detail="Invalid machine credentials")

    updated_machine = await sync_machine_runtime(
        machine,
        request=request,
        hostname=data.hostname,
        local_ip=data.local_ip,
        public_ip=data.public_ip,
        is_active=data.is_active,
    )

    is_online = is_machine_online(updated_machine)
    updated_serialized_machine = serialize_machine(updated_machine)

    set_cached_machine_status(str(updated_machine["_id"]), is_online)

    response.headers["X-PortHub-Observed-IP"] = updated_serialized_machine["public_ip"]
    await emit_machine_status_changed(updated_machine)

    config_bundle = await build_machine_config_bundle(updated_machine, request=request)

    return {
        "msg": "Machine synced successfully",
        "data": updated_serialized_machine,
        "config": config_bundle,
        "endpoints": build_machine_endpoints(updated_machine, request=request),
    }
