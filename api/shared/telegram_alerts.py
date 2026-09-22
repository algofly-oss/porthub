from shared.factory import db
from shared.telegram_client import send_telegram_message


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


async def send_instant_status_alert(machine: dict, *, is_online: bool) -> None:
    if machine.get("enabled", True) is False or is_machine_excluded_from_alerts(machine):
        return

    user = await db.users.find_one({"_id": machine["user_id"]})
    config = user_telegram_config(user)
    if not config["alerts_enabled"] or not config["instant_alerts_enabled"]:
        return
    if not config["bot_token"] or not config["chat_ids"]:
        return

    machine_name = machine.get("name") or "Machine"
    if is_online:
        text = f"\U0001F7E2 <b>{machine_name}</b> is back online"
    else:
        text = f"\U0001F534 <b>{machine_name}</b> went offline"

    await send_telegram_message(config["bot_token"], config["chat_ids"], text)
