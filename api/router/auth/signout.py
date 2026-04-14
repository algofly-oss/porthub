from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import redis
from shared.env import SESSION_COOKIE_NAME

router = APIRouter()


@router.post("/signout")
async def signout(request: Request, response: Response):
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return {"msg": "user not logged in"}

    redis.delete(session_token)
    response.delete_cookie(key=SESSION_COOKIE_NAME)

    return {"msg": "success"}
