from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db
from bson import ObjectId
from ..auth.common import authenticate_user
import random

router = APIRouter()


@router.get("/list")
async def list_connections(request: Request, response: Response):
    # Check if user is logged in
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    data = await db.connections.find({"user_id": user["_id"]}).to_list(length=None)

    for i in range(len(data)):
        data[i]["_id"] = str(data[i]["_id"])
        data[i]["user_id"] = str(data[i]["user_id"])

    # return dummy data
    return {
        "msg": "Connections listed successfully",
        "data": data
    }


@router.get("/random")
async def get_random_port(request: Request, response: Response):
    random_port = random.randint(10000, 65535)
    while await db.connections.find_one({"external_port": random_port}):
        random_port = random.randint(10000, 65535)

    return {
        "port": random_port
    }


@router.get("/external-port/{port}/availability")
async def external_port_availability(
    port: int,
    request: Request,
    response: Response,
    data_id: str | None = None,
):
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port")

    query = {"external_port": port}
    if data_id:
        if not ObjectId.is_valid(data_id):
            raise HTTPException(status_code=400, detail="Invalid connection id")
        query["_id"] = {"$ne": ObjectId(data_id)}

    connection = await db.connections.find_one(query)

    return {
        "available": connection is None,
        "message": None if connection is None else "External port is already assigned",
    }
