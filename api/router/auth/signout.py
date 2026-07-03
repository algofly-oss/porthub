from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db, redis
from shared.env import SESSION_COOKIE_NAME
from .session_utils import revoke_session_record

router = APIRouter()


@router.post("/signout")
async def signout(request: Request, response: Response):
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return {"msg": "user not logged in"}

    await revoke_session_record(db, redis, session_token)
    response.delete_cookie(key=SESSION_COOKIE_NAME)

    return {"msg": "success"}
