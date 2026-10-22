from fastapi import HTTPException, Request
from shared.sessions import session_user_id
from shared.env import SESSION_COOKIE_NAME
from pydantic import BaseModel


class UserSignupDto(BaseModel):
    name: str
    username: str
    password: str
    invitation_token: str | None = None


class UserSigninDto(BaseModel):
    username: str
    password: str


class UserPasswordUpdateDto(BaseModel):
    current_password: str
    new_password: str


def get_session_token(request: Request, default=None):
    return request.cookies.get(SESSION_COOKIE_NAME, default)


async def authenticate_user(session_token):
    """User id (str) for the request's session, or 400 when not signed in."""
    login_error = HTTPException(status_code=400, detail="User not logged in")
    if isinstance(session_token, Request):
        session_token = get_session_token(session_token)
    user_id = await session_user_id(session_token)
    if not user_id:
        raise login_error
    return user_id
