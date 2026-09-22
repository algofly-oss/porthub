import typing

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from shared.factory import db
from shared.telegram_client import send_telegram_message
from .common import authenticate_user

router = APIRouter()

VALID_DIGEST_INTERVAL_HOURS = {1, 3, 6, 12, 24}
MAX_CHAT_IDS = 20


class TelegramSettingsUpdate(BaseModel):
    bot_token: typing.Optional[str] = Field(None)
    chat_ids: typing.Optional[typing.List[str]] = Field(None)
    alerts_enabled: typing.Optional[bool] = Field(None)
    instant_alerts_enabled: typing.Optional[bool] = Field(None)
    digest_enabled: typing.Optional[bool] = Field(None)
    digest_interval_hours: typing.Optional[int] = Field(None)


def _user_object_id(request: Request) -> ObjectId:
    user_id = authenticate_user(request)
    if isinstance(user_id, bytes):
        user_id = user_id.decode("utf-8")
    return ObjectId(str(user_id))


def _mask_bot_token(bot_token: str) -> str:
    bot_token = (bot_token or "").strip()
    if not bot_token:
        return ""
    if len(bot_token) <= 4:
        return "*" * len(bot_token)
    return f"{'*' * (len(bot_token) - 4)}{bot_token[-4:]}"


def _serialize_telegram_settings(user: dict) -> dict:
    return {
        "bot_token_masked": _mask_bot_token(user.get("telegram_bot_token") or ""),
        "has_bot_token": bool(user.get("telegram_bot_token")),
        "chat_ids": user.get("telegram_chat_ids") or [],
        "alerts_enabled": bool(user.get("telegram_alerts_enabled", False)),
        "instant_alerts_enabled": bool(user.get("telegram_instant_alerts_enabled", True)),
        "digest_enabled": bool(user.get("telegram_digest_enabled", True)),
        "digest_interval_hours": int(user.get("telegram_digest_interval_hours") or 6),
    }


@router.get("/telegram")
async def get_telegram_settings(request: Request):
    user_object_id = _user_object_id(request)
    user = await db.users.find_one({"_id": user_object_id})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")
    return _serialize_telegram_settings(user)


@router.patch("/telegram")
async def update_telegram_settings(data: TelegramSettingsUpdate, request: Request):
    user_object_id = _user_object_id(request)
    user = await db.users.find_one({"_id": user_object_id})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    updates: dict = {}

    if data.bot_token is not None:
        updates["telegram_bot_token"] = data.bot_token.strip()

    if data.chat_ids is not None:
        chat_ids = [str(chat_id).strip() for chat_id in data.chat_ids if str(chat_id).strip()]
        if len(chat_ids) > MAX_CHAT_IDS:
            raise HTTPException(
                status_code=400,
                detail=f"You can configure at most {MAX_CHAT_IDS} chat/channel IDs",
            )
        updates["telegram_chat_ids"] = chat_ids

    if data.alerts_enabled is not None:
        updates["telegram_alerts_enabled"] = bool(data.alerts_enabled)

    if data.instant_alerts_enabled is not None:
        updates["telegram_instant_alerts_enabled"] = bool(data.instant_alerts_enabled)

    if data.digest_enabled is not None:
        updates["telegram_digest_enabled"] = bool(data.digest_enabled)

    if data.digest_interval_hours is not None:
        if data.digest_interval_hours not in VALID_DIGEST_INTERVAL_HOURS:
            raise HTTPException(
                status_code=400,
                detail="Digest interval must be one of 1, 3, 6, 12, or 24 hours",
            )
        updates["telegram_digest_interval_hours"] = data.digest_interval_hours

    if updates:
        await db.users.update_one({"_id": user_object_id}, {"$set": updates})

    updated_user = await db.users.find_one({"_id": user_object_id})
    return _serialize_telegram_settings(updated_user)


@router.post("/telegram/test")
async def send_test_telegram_message(request: Request):
    user_object_id = _user_object_id(request)
    user = await db.users.find_one({"_id": user_object_id})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    bot_token = (user.get("telegram_bot_token") or "").strip()
    chat_ids = user.get("telegram_chat_ids") or []
    if not bot_token or not chat_ids:
        raise HTTPException(
            status_code=400,
            detail="Add a bot token and at least one chat ID before sending a test message",
        )

    result = await send_telegram_message(
        bot_token, chat_ids, "✅ PortHub Telegram alerts are set up correctly."
    )
    if not result["sent"]:
        raise HTTPException(
            status_code=400,
            detail="Could not deliver the test message. Check the bot token and chat IDs.",
        )

    return {"msg": "success", "sent": result["sent"], "failed": result["failed"]}
