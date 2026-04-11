import secrets
import string
from datetime import datetime

from bson import ObjectId
from fastapi import HTTPException, Request

from shared.factory import db
from .auth.common import authenticate_user


def parse_object_id(value: str, detail: str) -> ObjectId:
    if not value or not ObjectId.is_valid(value):
        raise HTTPException(status_code=400, detail=detail)
    return ObjectId(value)


async def get_authenticated_user(request: Request):
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one(
        {"_id": parse_object_id(user_id.decode("utf-8"), "User not logged in")}
    )
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")
    return user


def utcnow():
    return datetime.utcnow()


async def generate_machine_token() -> str:
    alphabet = string.ascii_letters + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(48))
    while await db.machines.find_one({"token": token}):
        token = "".join(secrets.choice(alphabet) for _ in range(48))
    return token


def serialize_machine(machine: dict):
    return {
        "_id": str(machine["_id"]),
        "user_id": str(machine["user_id"]),
        "name": machine.get("name", ""),
        "hostname": machine.get("hostname", ""),
        "local_ip": machine.get("local_ip", machine.get("ip_address", "")),
        "public_ip": machine.get("public_ip", ""),
        "token": machine.get("token", ""),
        "is_active": machine.get("is_active", False),
        "last_seen_at": machine.get("last_seen_at"),
        "created_at": machine.get("created_at"),
        "updated_at": machine.get("updated_at"),
    }


def serialize_connection(connection: dict, machine: dict | None = None):
    machine_id = connection.get("machine_id")
    serialized = {
        "_id": str(connection["_id"]),
        "user_id": str(connection["user_id"]),
        "machine_id": str(machine_id) if machine_id else "",
        "service_name": connection.get("service_name", ""),
        "service_description": connection.get("service_description", ""),
        "internal_port": connection.get("internal_port"),
        "external_port": connection.get("external_port"),
        "enabled": connection.get("enabled", True),
        "created_at": connection.get("created_at"),
        "updated_at": connection.get("updated_at"),
    }

    if machine:
        serialized["machine_name"] = machine.get("name", "")
        serialized["machine_hostname"] = machine.get("hostname", "")
        serialized["machine_local_ip"] = machine.get("local_ip", machine.get("ip_address", ""))
        serialized["machine_public_ip"] = machine.get("public_ip", "")
    else:
        serialized["machine_name"] = connection.get("host_name", "")
        serialized["machine_hostname"] = connection.get("host_id", "")
        serialized["machine_local_ip"] = connection.get("host_ip", "")
        serialized["machine_public_ip"] = ""

    return serialized
