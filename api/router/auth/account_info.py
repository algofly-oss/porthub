from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db, redis
from shared.env import SESSION_COOKIE_NAME
from bson import ObjectId
from .account_update import serialize_user
from .common import authenticate_user, get_session_token
from .session_utils import (
    create_session_record,
    revoke_session_record,
    serialize_session,
    touch_session_record,
)

router = APIRouter()


@router.get("/me")
async def account_info(request: Request, response: Response):
    # Check if user is logged in
    user_id = authenticate_user(request.cookies.get(SESSION_COOKIE_NAME))
    user_id_string = user_id.decode("utf-8") if isinstance(user_id, bytes) else str(user_id)
    session_token = get_session_token(request, "")
    if await touch_session_record(db, session_token, request) == 0:
        await create_session_record(db, user_id_string, session_token, request)

    user = await db.users.find_one({"_id": ObjectId(user_id_string)})

    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    return serialize_user(user)


@router.get("/sessions")
async def list_sessions(request: Request):
    user_id = authenticate_user(request.cookies.get(SESSION_COOKIE_NAME))
    user_id_string = user_id.decode("utf-8") if isinstance(user_id, bytes) else str(user_id)
    session_token = get_session_token(request, "")
    if await touch_session_record(db, session_token, request) == 0:
        await create_session_record(db, user_id_string, session_token, request)

    sessions = (
        await db.user_sessions.find(
            {
                "user_id": user_id_string,
                "revoked_at": None,
            }
        )
        .sort("last_accessed_at", -1)
        .to_list(length=100)
    )

    return {
        "data": [
            serialize_session(session, current_session_token=session_token)
            for session in sessions
        ]
    }


@router.delete("/sessions/{session_id}")
async def revoke_session(session_id: str, request: Request, response: Response):
    user_id = authenticate_user(request.cookies.get(SESSION_COOKIE_NAME))
    user_id_string = user_id.decode("utf-8") if isinstance(user_id, bytes) else str(user_id)

    session = await db.user_sessions.find_one(
        {
            "_id": session_id,
            "user_id": user_id_string,
            "revoked_at": None,
        }
    )
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    await revoke_session_record(db, redis, session_id)
    if session_id == get_session_token(request, ""):
        response.delete_cookie(key=SESSION_COOKIE_NAME)

    return {"msg": "success"}
