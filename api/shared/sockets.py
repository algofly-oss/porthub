import asyncio
import re
from typing import Any

import socketio
from bson import ObjectId
from fastapi.encoders import jsonable_encoder

from router.common import is_machine_online, serialize_machine
from shared.env import MACHINE_ONLINE_TTL_SECONDS
from shared.factory import db, redis

sio = socketio.AsyncServer(
    async_mode="asgi", cors_allowed_origins=[]
)  # [] works for all origins, [*] wasn't working

CTS_MACHINE_STATUS_SNAPSHOT = "/cts/machines/status-snapshot"
STC_MACHINE_STATUS_SNAPSHOT = "/stc/machines/status-snapshot"
STC_MACHINE_STATUS_CHANGED = "/stc/machines/status-changed"

_MACHINE_STATUS_MONITOR_INTERVAL_SECONDS = max(5, min(30, MACHINE_ONLINE_TTL_SECONDS // 2 or 5))
_machine_status_cache: dict[str, bool] = {}


def _get_session_token(environ: dict[str, Any]) -> str | None:
    pattern = r"session_token=([^;]+)"
    match = re.search(pattern, environ.get("HTTP_COOKIE", ""))
    return match.group(1) if match else None


def _get_user_id_from_session_token(session_token: str | None) -> str | None:
    if not session_token:
        return None

    user_id = redis.get(session_token)
    if not user_id:
        return None

    return user_id.decode()


def _serialize_machine_status_payload(machine: dict) -> dict[str, Any]:
    return {"machine": serialize_machine(machine)}


def set_cached_machine_status(machine_id: str, is_online: bool) -> None:
    _machine_status_cache[str(machine_id)] = is_online


def remove_cached_machine_status(machine_id: str) -> None:
    _machine_status_cache.pop(str(machine_id), None)


async def emit(event_name: str, data: Any, user_id: str, room: str | None = None) -> None:
    target_room = room or str(user_id)
    await sio.emit(event_name, data=jsonable_encoder(data), room=target_room)


async def emit_machine_status_changed(machine: dict, room: str | None = None) -> None:
    user_id = str(machine["user_id"])
    await emit(
        STC_MACHINE_STATUS_CHANGED,
        _serialize_machine_status_payload(machine),
        user_id=user_id,
        room=room,
    )


async def emit_machine_status_snapshot(user_id: str, room: str | None = None) -> None:
    machines = await db.machines.find(
        {"user_id": ObjectId(user_id)}
    ).sort("created_at", 1).to_list(None)
    await emit(
        STC_MACHINE_STATUS_SNAPSHOT,
        {"machines": [serialize_machine(machine) for machine in machines]},
        user_id=user_id,
        room=room,
    )


async def initialize_machine_status_cache() -> None:
    machines = await db.machines.find({}).to_list(None)
    _machine_status_cache.clear()
    for machine in machines:
        set_cached_machine_status(str(machine["_id"]), is_machine_online(machine))


async def monitor_machine_statuses(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        machines = await db.machines.find({}).to_list(None)
        next_machine_status_cache: dict[str, bool] = {}

        for machine in machines:
            machine_id = str(machine["_id"])
            is_online = is_machine_online(machine)
            previous_status = _machine_status_cache.get(machine_id)

            next_machine_status_cache[machine_id] = is_online

            if previous_status is not None and previous_status != is_online:
                await emit_machine_status_changed(machine)

        _machine_status_cache.clear()
        _machine_status_cache.update(next_machine_status_cache)

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=_MACHINE_STATUS_MONITOR_INTERVAL_SECONDS,
            )
        except asyncio.TimeoutError:
            continue


@sio.event
async def connect(sid, environ, auth):
    user_id = _get_user_id_from_session_token(_get_session_token(environ))
    if user_id:
        await sio.save_session(sid, {"user_id": user_id})
        await sio.enter_room(sid, user_id)

    await sio.emit("join", {"sid": sid}, room=sid)


@sio.on(CTS_MACHINE_STATUS_SNAPSHOT)
async def handle_machine_status_snapshot(sid, data=None):
    try:
        session = await sio.get_session(sid)
    except KeyError:
        return

    user_id = session.get("user_id")

    if not user_id:
        return

    await emit_machine_status_snapshot(user_id=user_id, room=sid)


@sio.event
async def disconnect(sid):
    return None
