from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db
from shared.sessions import session_user_id, start_session
from shared.env import SESSION_COOKIE_NAME
from .common import UserSigninDto
import bcrypt

router = APIRouter()


@router.post("/signin")
async def signin(user: UserSigninDto, request: Request, response: Response):
    """
    Sign in a user.


    **Parameters**:
    - `username` (str): The email/phone of the user.
    - `password` (str): The password of the user.

    **Returns**:
    - `msg` (str): The message of the response.
    """

    # Check if user is already logged in
    if await session_user_id(request.cookies.get(SESSION_COOKIE_NAME, "")):
        return {"msg": "success"}

    # Check if user exists
    existing_user = await db.users.find_one({"username": user.username})

    if not existing_user:
        raise HTTPException(status_code=400, detail="incorrect username")

    # Check if password is correct
    if bcrypt.checkpw(user.password.encode("utf-8"), existing_user["password"]):
        # create a new session token
        await start_session(existing_user.get("_id"), request, response)
        return {"msg": "success"}

    raise HTTPException(status_code=400, detail="incorrect password")
