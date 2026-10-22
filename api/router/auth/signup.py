from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db, redis
from shared.env import SESSION_COOKIE_NAME, SIGNUP_DISABLED
from .common import UserSignupDto
from .session_utils import create_session_record
from shared.workspaces import valid_invitation, accept_invitation
import re
import datetime
import bcrypt
import uuid


router = APIRouter()


@router.post("/signup")
async def signup(user: UserSignupDto, request: Request, response: Response):
    """
    Create a new user.


    **Parameters**:
    - `name` (str): The name of the user.
    - `username` (str): The email/phone of the user.
    - `password` (str): The password of the user.

    **Returns**:
    - `msg` (str): The message of the response.
    """

    invitation_token = user.invitation_token
    if invitation_token:
        invite = await valid_invitation(invitation_token)
        if user.username.strip().lower() != invite["email"]:
            raise HTTPException(403, "Use the email address on the invitation")
        if not user.name.strip() or len(user.name) > 100 or not 12 <= len(user.password.encode("utf-8")) <= 72:
            raise HTTPException(400, "Provide a name and a password between 12 and 72 bytes")
        user.username = invite["email"]
        if await db.users.find_one({"username": {"$regex": f"^{re.escape(user.username)}$", "$options": "i"}}):
            raise HTTPException(409, "An account already exists. Sign in to accept the invitation.")
        # Required to make concurrent invited signups atomic. Existing duplicate
        # usernames must be resolved by an administrator, never merged silently.
        try:
            await db.users.create_index("username", unique=True)
        except Exception:
            raise HTTPException(409, "An administrator must resolve duplicate account names before invited registration")
    if SIGNUP_DISABLED and not invitation_token:
        raise HTTPException(status_code=403, detail="sign up is disabled")

    # Check if user already exists
    if await db.users.find_one({"username": user.username}):
        return {"msg": "user already exists"}

    # Create a new user
    salt = bcrypt.gensalt()
    await db.users.insert_one(
        {
            "name": user.name,
            "username": user.username,
            "password": bcrypt.hashpw(user.password.encode("utf-8"), salt),
            "role": "user",
            "salt": salt,
            "created_at": datetime.datetime.utcnow(),
        }
    )

    # find the created user_id
    user = await db.users.find_one({"username": user.username})
    workspace_id = await accept_invitation(user, invitation_token) if invitation_token else None
    user_id = str(user.get("_id"))

    # create a new session token
    session_token = str(uuid.uuid4())
    redis.set(session_token, user_id)
    await create_session_record(db, user_id, session_token, request)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=session_token, httponly=True)

    return {"msg": "success", **({"workspace_id": workspace_id} if workspace_id else {})}
