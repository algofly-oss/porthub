from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.rathole_config import rebuild_server_toml
from ..common import (
    generate_machine_token,
    get_authenticated_user,
    serialize_machine,
    utcnow,
)
from .models.machine import Machine

router = APIRouter()


@router.post("/add")
async def add_machine(data: Machine, request: Request):
    user = await get_authenticated_user(request)
    now = utcnow()
    machine_name = data.name.strip()

    if not machine_name:
        raise HTTPException(status_code=400, detail="Machine name is required")

    machine = {
        "user_id": user["_id"],
        "name": machine_name,
        "hostname": (data.hostname or "").strip(),
        "enabled": True if data.enabled is None else bool(data.enabled),
        "local_ip": "",
        "public_ip": "",
        "token": await generate_machine_token(),
        "log_tokens": [],
        "auth_required": False,
        "last_seen_at": None,
        "created_at": now,
        "updated_at": now,
    }

    result = await db.machines.insert_one(machine)
    created_machine = await db.machines.find_one({"_id": result.inserted_id})
    await rebuild_server_toml(allow_empty=True)

    return {
        "msg": "Machine added successfully",
        "data": serialize_machine(created_machine),
    }
