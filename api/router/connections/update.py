from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db
from bson import ObjectId
from ..auth.common import authenticate_user
from .models.connection import Connection

router = APIRouter()

@router.put("/update")
async def update_connection(data: Connection, request: Request):
    # Check if user is logged in
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    # Check if connection already exists
    connection = await db.connections.find_one(
        {"_id": ObjectId(data.data_id), "user_id": user["_id"]}
    )
    if not connection:
        raise HTTPException(status_code=400, detail="Connection not found")

    existing_port = await db.connections.find_one({
        "external_port": data.external_port,
        "_id": {"$ne": connection["_id"]},
    })
    if existing_port:
        raise HTTPException(status_code=400, detail="Port already in use")

    # Update connection
    await db.connections.update_one({"_id": connection["_id"]}, {"$set": {
        "host_id": data.host_id,
        "host_name": data.host_name,
        "host_ip": data.host_ip,
        "service_name": data.service_name,
        "service_description": data.service_description or "",
        "internal_port": data.internal_port,
        "external_port": data.external_port,
        "enabled": True if data.enabled is None else data.enabled,
    }})

    res = await db.connections.find_one({"_id": connection["_id"]})
    res["_id"] = str(res["_id"])
    res["user_id"] = str(res["user_id"])

    return {
        "msg": "Connection updated successfully",
        "data": res
    }
