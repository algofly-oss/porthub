import asyncio
import logging
from datetime import datetime, timedelta

from router.common import get_machine_connection_status
from shared.factory import db
from shared.sockets import hold_background_leadership
from shared.telegram_alerts import is_machine_excluded_from_alerts, user_telegram_config
from shared.telegram_client import format_last_seen, send_telegram_message

logger = logging.getLogger(__name__)

DIGEST_POLL_INTERVAL_SECONDS = 600


def _utcnow() -> datetime:
    return datetime.utcnow()


def _is_digest_due(user: dict, config: dict, now: datetime) -> bool:
    last_sent_at = user.get("telegram_last_batch_alert_at")
    if not isinstance(last_sent_at, datetime):
        return True
    interval = timedelta(hours=max(1, config["digest_interval_hours"]))
    return now - last_sent_at >= interval


async def _send_offline_digest_for_user(user: dict, config: dict, now: datetime) -> None:
    machines = await db.machines.find(
        {
            "user_id": user["_id"],
            "deletion_pending": {"$ne": True},
            "enabled": {"$ne": False},
            "telegram_alerts_excluded": {"$ne": True},
        }
    ).to_list(None)

    offline_machines = [
        machine
        for machine in machines
        if get_machine_connection_status(machine) == "offline"
        and not is_machine_excluded_from_alerts(machine)
    ]

    if offline_machines:
        lines = ["\U0001F4E1 <b>Machines still offline</b>"]
        for machine in offline_machines:
            name = machine.get("name") or "Machine"
            last_seen_label = format_last_seen(machine.get("last_seen_at"), now=now)
            lines.append(f"• {name} — last seen {last_seen_label}")
        await send_telegram_message(
            config["bot_token"], config["chat_ids"], "\n".join(lines)
        )

    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"telegram_last_batch_alert_at": now}},
    )


async def monitor_offline_digest(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        if not hold_background_leadership():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=DIGEST_POLL_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass
            continue

        now = _utcnow()
        users = await db.users.find(
            {
                "telegram_alerts_enabled": True,
                "telegram_digest_enabled": True,
                "telegram_bot_token": {"$exists": True, "$ne": ""},
            }
        ).to_list(None)

        for user in users:
            if stop_event.is_set():
                break

            config = user_telegram_config(user)
            if not config["bot_token"] or not config["chat_ids"]:
                continue
            if not _is_digest_due(user, config, now):
                continue

            try:
                await _send_offline_digest_for_user(user, config, now)
            except Exception:
                logger.exception(
                    "Failed to send Telegram offline digest for user %s", user["_id"]
                )

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=DIGEST_POLL_INTERVAL_SECONDS,
            )
        except asyncio.TimeoutError:
            continue
