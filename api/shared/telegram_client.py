import asyncio
import logging
from datetime import datetime, timedelta

import requests

logger = logging.getLogger(__name__)

TELEGRAM_API_BASE_URL = "https://api.telegram.org"
TELEGRAM_REQUEST_TIMEOUT_SECONDS = 10


def _send_telegram_message_sync(bot_token: str, chat_id: str, text: str) -> None:
    url = f"{TELEGRAM_API_BASE_URL}/bot{bot_token}/sendMessage"
    response = requests.post(
        url,
        json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
        timeout=TELEGRAM_REQUEST_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Telegram API returned {response.status_code}: {response.text[:200]}"
        )


async def send_telegram_message(bot_token: str, chat_ids: list[str], text: str) -> dict:
    bot_token = (bot_token or "").strip()
    chat_ids = [str(chat_id).strip() for chat_id in (chat_ids or []) if str(chat_id).strip()]

    if not bot_token or not chat_ids:
        return {"sent": [], "failed": []}

    sent: list[str] = []
    failed: list[str] = []

    for chat_id in chat_ids:
        try:
            await asyncio.to_thread(_send_telegram_message_sync, bot_token, chat_id, text)
            sent.append(chat_id)
        except Exception:
            logger.exception("Failed to send Telegram message to chat %s", chat_id)
            failed.append(chat_id)

    return {"sent": sent, "failed": failed}


def format_offline_duration(delta: timedelta) -> str:
    total_seconds = max(0, int(delta.total_seconds()))

    if total_seconds < 60:
        return "just now"

    total_minutes = total_seconds // 60
    if total_minutes < 60:
        return f"{total_minutes}m ago"

    total_hours = total_minutes // 60
    if total_hours < 24:
        return f"{total_hours}h ago"

    total_days = total_hours // 24
    return f"{total_days}d ago"


def format_last_seen(last_seen_at: datetime | None, *, now: datetime | None = None) -> str:
    if not isinstance(last_seen_at, datetime):
        return "never"
    now = now or datetime.utcnow()
    return format_offline_duration(now - last_seen_at)
