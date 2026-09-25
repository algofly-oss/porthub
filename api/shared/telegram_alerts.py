from datetime import datetime, timedelta

from router.common import get_machine_connection_status
from shared.env import MACHINE_OFFLINE_ALERT_GRACE_SECONDS, MACHINE_ONLINE_TTL_SECONDS
from shared.factory import db
from shared.telegram_client import format_last_seen, send_telegram_message


def user_telegram_config(user: dict | None) -> dict:
    return {
        "bot_token": (user or {}).get("telegram_bot_token") or "",
        "chat_ids": (user or {}).get("telegram_chat_ids") or [],
        "alerts_enabled": bool((user or {}).get("telegram_alerts_enabled", False)),
        "instant_alerts_enabled": bool(
            (user or {}).get("telegram_instant_alerts_enabled", True)
        ),
        "digest_enabled": bool((user or {}).get("telegram_digest_enabled", True)),
        "digest_interval_hours": int((user or {}).get("telegram_digest_interval_hours") or 6),
    }


def is_machine_excluded_from_alerts(machine: dict) -> bool:
    return bool(machine.get("telegram_alerts_excluded", False))


async def _send_instant_alert(machine: dict, text: str) -> None:
    user = await db.users.find_one({"_id": machine["user_id"]})
    config = user_telegram_config(user)
    if not config["alerts_enabled"] or not config["instant_alerts_enabled"]:
        return
    if not config["bot_token"] or not config["chat_ids"]:
        return

    await send_telegram_message(config["bot_token"], config["chat_ids"], text)


async def mark_existing_offline_machines_alerted() -> None:
    """Treat machines already offline at startup as alerted, so a deploy does
    not re-announce long-dead machines but they still get a back-online alert."""
    stale_before = datetime.utcnow() - timedelta(
        seconds=MACHINE_ONLINE_TTL_SECONDS + MACHINE_OFFLINE_ALERT_GRACE_SECONDS
    )
    await db.machines.update_many(
        {
            "telegram_offline_alerted": {"$exists": False},
            "last_seen_at": {"$lt": stale_before},
        },
        {"$set": {"telegram_offline_alerted": True}},
    )


async def process_machine_status_alert(machine: dict, *, now: datetime) -> None:
    """Sends an offline alert once a machine has been offline (as shown in the
    UI) for the grace period, and a back-online alert only for machines whose
    offline alert was actually sent, so short blips produce no alerts."""
    if machine.get("enabled", True) is False or is_machine_excluded_from_alerts(machine):
        return

    status = get_machine_connection_status(machine)
    offline_alerted = bool(machine.get("telegram_offline_alerted", False))
    machine_name = machine.get("name") or "Machine"
    last_seen_at = machine.get("last_seen_at")

    if status == "offline" and not offline_alerted:
        if not isinstance(last_seen_at, datetime):
            return
        alert_after = timedelta(
            seconds=MACHINE_ONLINE_TTL_SECONDS + MACHINE_OFFLINE_ALERT_GRACE_SECONDS
        )
        if now - last_seen_at < alert_after:
            return
        await db.machines.update_one(
            {"_id": machine["_id"]}, {"$set": {"telegram_offline_alerted": True}}
        )
        await _send_instant_alert(
            machine,
            f"\U0001F534 <b>{machine_name}</b> went offline"
            f" (last seen {format_last_seen(last_seen_at, now=now)})",
        )
    elif status != "offline" and offline_alerted:
        await db.machines.update_one(
            {"_id": machine["_id"]}, {"$set": {"telegram_offline_alerted": False}}
        )
        await _send_instant_alert(machine, f"\U0001F7E2 <b>{machine_name}</b> is back online")
