import pydantic
from fastapi import APIRouter, HTTPException, Request

from shared.factory import db
from shared.sockets import emit_machine_status_changed, set_cached_machine_status
from ..common import (
    get_authenticated_user,
    get_machine_group_object_ids,
    is_machine_online,
    parse_object_id,
    serialize_machine,
    utcnow,
)

router = APIRouter()


class MachineGroupMember(pydantic.BaseModel):
    machine_id: str
    group_id: str


@router.post("/groups/add")
async def add_machine_to_group(data: MachineGroupMember, request: Request):
    user = await get_authenticated_user(request)
    machine_oid = parse_object_id(data.machine_id, "Invalid machine id")
    group_oid = parse_object_id(data.group_id, "Invalid group id")

    machine = await db.machines.find_one({"_id": machine_oid, "user_id": user["_id"]})
    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    group = await db.machine_groups.find_one({"_id": group_oid, "user_id": user["_id"]})
    if not group:
        raise HTTPException(status_code=400, detail="Group not found")

    current = get_machine_group_object_ids(machine)
    if group_oid in current:
        updated = await db.machines.find_one({"_id": machine_oid})
        return {
            "msg": "Machine is already in this group",
            "data": serialize_machine(updated),
        }

    new_ids = [*current, group_oid]
    now = utcnow()
    await db.machines.update_one(
        {"_id": machine_oid},
        {"$set": {"group_ids": new_ids, "updated_at": now}, "$unset": {"group_id": ""}},
    )

    updated = await db.machines.find_one({"_id": machine_oid})
    set_cached_machine_status(str(updated["_id"]), is_machine_online(updated))
    await emit_machine_status_changed(updated)

    return {
        "msg": "Machine added to group successfully",
        "data": serialize_machine(updated),
    }


@router.post("/groups/remove")
async def remove_machine_from_group(data: MachineGroupMember, request: Request):
    user = await get_authenticated_user(request)
    machine_oid = parse_object_id(data.machine_id, "Invalid machine id")
    group_oid = parse_object_id(data.group_id, "Invalid group id")

    machine = await db.machines.find_one({"_id": machine_oid, "user_id": user["_id"]})
    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    group = await db.machine_groups.find_one({"_id": group_oid, "user_id": user["_id"]})
    if not group:
        raise HTTPException(status_code=400, detail="Group not found")

    current = get_machine_group_object_ids(machine)
    now = utcnow()

    if group_oid in current:
        new_ids = [oid for oid in current if oid != group_oid]
        await db.machines.update_one(
            {"_id": machine_oid},
            {"$set": {"group_ids": new_ids, "updated_at": now}, "$unset": {"group_id": ""}},
        )
    elif machine.get("group_id") == group_oid:
        await db.machines.update_one(
            {"_id": machine_oid},
            {"$unset": {"group_id": ""}, "$set": {"updated_at": now}},
        )
    else:
        raise HTTPException(status_code=400, detail="Machine is not in this group")

    updated = await db.machines.find_one({"_id": machine_oid})
    set_cached_machine_status(str(updated["_id"]), is_machine_online(updated))
    await emit_machine_status_changed(updated)

    return {
        "msg": "Machine removed from group successfully",
        "data": serialize_machine(updated),
    }
