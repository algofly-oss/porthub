from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request
import bcrypt
import re
from shared.factory import db
from shared.env import SIGNUP_DISABLED, SESSION_COOKIE_NAME
from .common import UserPasswordUpdateDto, authenticate_user

router = APIRouter()
PASSWORD_REGEX = re.compile(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$")


@router.get("/settings")
async def auth_settings():
    return {
        "signup_disabled": SIGNUP_DISABLED,
        "signup_enabled": not SIGNUP_DISABLED,
    }


@router.put("/settings/password")
async def update_password(data: UserPasswordUpdateDto, request: Request):
    user_id = authenticate_user(request.cookies.get(SESSION_COOKIE_NAME))
    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})

    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    if not bcrypt.checkpw(
        data.current_password.encode("utf-8"),
        user["password"],
    ):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different from the current password",
        )

    if not PASSWORD_REGEX.match(data.new_password):
        raise HTTPException(
            status_code=400,
            detail="New password must include uppercase, lowercase, number, and symbol",
        )

    salt = bcrypt.gensalt()
    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password": bcrypt.hashpw(data.new_password.encode("utf-8"), salt),
                "salt": salt,
            }
        },
    )

    return {"msg": "password updated"}
