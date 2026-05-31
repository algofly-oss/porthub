import asyncio
import logging
from datetime import datetime, timedelta

from shared.factory import db
from shared.firewall_client import sync_connection_firewall_policy
from shared.rathole_config import rebuild_server_toml
from shared.sockets import emit_machine_config_changed

logger = logging.getLogger(__name__)

REFRESH_POLL_INTERVAL_SECONDS = 30
REFRESH_REENABLE_DELAY_SECONDS = 5
REFRESH_RETRY_DELAY_SECONDS = 60


def _utcnow() -> datetime:
    return datetime.utcnow()


def _next_refresh_at(now: datetime, interval_minutes: int | None) -> datetime:
    safe_interval_minutes = max(1, int(interval_minutes or 60))
    return now + timedelta(minutes=safe_interval_minutes)


async def _apply_connection_enabled(connection: dict, enabled: bool) -> dict | None:
    now = _utcnow()
    await db.connections.update_one(
        {"_id": connection["_id"]},
        {
            "$set": {
                "enabled": enabled,
                "updated_at": now,
            }
        },
    )

    updated_connection = await db.connections.find_one({"_id": connection["_id"]})
    if not updated_connection:
        return None

    await rebuild_server_toml(allow_empty=True)
    if updated_connection.get("machine_id"):
        await emit_machine_config_changed(str(updated_connection["machine_id"]))
    await sync_connection_firewall_policy(updated_connection)
    return updated_connection


async def refresh_connection_config(connection: dict, *, force: bool = False) -> dict | None:
    connection_id = connection["_id"]
    interval_minutes = connection.get("auto_refresh_interval_minutes") or 60
    now = _utcnow()
    disabled_connection: dict | None = None
    reenabled = False

    machine = await db.machines.find_one(
        {
            "_id": connection.get("machine_id"),
            "enabled": {"$ne": False},
        }
    )
    if not machine:
        await db.connections.update_one(
            {"_id": connection_id},
            {
                "$set": {
                    "auto_refresh_next_at": (
                        _utcnow() + timedelta(seconds=REFRESH_RETRY_DELAY_SECONDS)
                        if connection.get("auto_refresh_enabled", False)
                        else None
                    ),
                }
            },
        )
        return None

    logger.warning(
        "Auto-refreshing connection %s on machine %s",
        connection_id,
        machine["_id"],
    )

    try:
        disabled_connection = await _apply_connection_enabled(connection, False)
        if not disabled_connection:
            return None

        await asyncio.sleep(REFRESH_REENABLE_DELAY_SECONDS)

        latest_connection = await db.connections.find_one({"_id": connection_id})
        if not latest_connection:
            return None

        if not force and not latest_connection.get("auto_refresh_enabled", False):
            await _apply_connection_enabled(latest_connection, True)
            reenabled = True
            return None

        refreshed_connection = await _apply_connection_enabled(latest_connection, True)
        if not refreshed_connection:
            return None
        reenabled = True

        refreshed_at = _utcnow()
        auto_refresh_enabled = bool(refreshed_connection.get("auto_refresh_enabled", False))
        await db.connections.update_one(
            {"_id": connection_id},
            {
                "$set": {
                    "auto_refreshed_at": refreshed_at,
                    "auto_refresh_next_at": (
                        _next_refresh_at(refreshed_at, interval_minutes)
                        if auto_refresh_enabled
                        else None
                    ),
                }
            },
        )
        return await db.connections.find_one({"_id": connection_id})
    except asyncio.CancelledError:
        latest_connection = await db.connections.find_one({"_id": connection_id})
        if disabled_connection and not reenabled and latest_connection:
            await asyncio.shield(_apply_connection_enabled(latest_connection, True))
        raise
    except Exception:
        logger.exception("Failed to auto-refresh connection %s", connection_id)
        latest_connection = await db.connections.find_one({"_id": connection_id})
        if disabled_connection and not reenabled and latest_connection:
            await _apply_connection_enabled(latest_connection, True)
        await db.connections.update_one(
            {"_id": connection_id},
            {
                "$set": {
                    "auto_refresh_next_at": (
                        _utcnow() + timedelta(seconds=REFRESH_RETRY_DELAY_SECONDS)
                        if connection.get("auto_refresh_enabled", False)
                        else None
                    ),
                }
            },
        )
        return None


async def monitor_connection_auto_refresh(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        now = _utcnow()
        due_connections = await db.connections.find(
            {
                "enabled": {"$ne": False},
                "auto_refresh_enabled": True,
                "auto_refresh_interval_minutes": {"$gte": 1},
                "$or": [
                    {"auto_refresh_next_at": {"$lte": now}},
                    {"auto_refresh_next_at": {"$exists": False}},
                    {"auto_refresh_next_at": None},
                ],
            }
        ).to_list(length=25)

        for connection in due_connections:
            if stop_event.is_set():
                break
            await refresh_connection_config(connection)

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=REFRESH_POLL_INTERVAL_SECONDS,
            )
        except asyncio.TimeoutError:
            pass
