from fastapi import HTTPException, Request

from ..common import get_authenticated_user


async def require_admin_user(request: Request):
    user = await get_authenticated_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
