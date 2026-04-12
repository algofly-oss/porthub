from fastapi import APIRouter
from shared.env import SIGNUP_DISABLED

router = APIRouter()


@router.get("/settings")
async def auth_settings():
    return {
        "signup_disabled": SIGNUP_DISABLED,
        "signup_enabled": not SIGNUP_DISABLED,
    }
