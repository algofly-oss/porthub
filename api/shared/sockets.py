import asyncio
import re
from typing import Any

import socketio
from bson import ObjectId
from fastapi.encoders import jsonable_encoder

from router.common import is_machine_online, serialize_machine
from shared.machine_client import authenticate_machine, build_machine_config_bundle
from shared.env import MACHINE_ONLINE_TTL_SECONDS
from shared.factory import db, redis

sio = socketio.AsyncServer(
    async_mode="asgi", cors_allowed_origins=[]
)  # [] works for all origins, [*] wasn't working

CTS_MACHINE_STATUS_SNAPSHOT = "/cts/machines/status-snapshot"
STC_MACHINE_STATUS_SNAPSHOT = "/stc/machines/status-snapshot"
STC_MACHINE_STATUS_CHANGED = "/stc/machines/status-changed"
CTS_MACHINE_CONFIG_SNAPSHOT = "/cts/machines/config-snapshot"
STC_MACHINE_CONFIG_SNAPSHOT = "/stc/machines/config-snapshot"
STC_MACHINE_CONFIG_CHANGED = "/stc/machines/config-changed"
CTS_MACHINE_LOG_STREAM_SUBSCRIBE = "/cts/machines/log-stream-subscribe"
CTS_MACHINE_LOG_STREAM_UNSUBSCRIBE = "/cts/machines/log-stream-unsubscribe"
STC_MACHINE_LOG_STREAM_STATUS = "/stc/machines/log-stream-status"
STC_MACHINE_LOG_STREAM_LINE = "/stc/machines/log-stream-line"

_MACHINE_STATUS_MONITOR_INTERVAL_SECONDS = max(5, min(30, MACHINE_ONLINE_TTL_SECONDS // 2 or 5))
_machine_status_cache: dict[str, bool] = {}
_machine_sids_by_machine_id: dict[str, set[str]] = {}
_machine_id_by_sid: dict[str, str] = {}
_log_stream_subscribers_by_machine_id: dict[str, set[str]] = {}
_log_stream_machine_ids_by_sid: dict[str, set[str]] = {}


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


def get_machine_room(machine_id: str) -> str:
    return f"machine:{machine_id}"


def get_machine_log_room(machine_id: str) -> str:
    return f"machine-log:{machine_id}"


def set_cached_machine_status(machine_id: str, is_online: bool) -> None:
    _machine_status_cache[str(machine_id)] = is_online


def remove_cached_machine_status(machine_id: str) -> None:
    _machine_status_cache.pop(str(machine_id), None)


def register_machine_sid(machine_id: str, sid: str) -> None:
    _machine_sids_by_machine_id.setdefault(machine_id, set()).add(sid)
    _machine_id_by_sid[sid] = machine_id


def unregister_machine_sid(sid: str) -> None:
    machine_id = _machine_id_by_sid.pop(sid, None)
    if not machine_id:
        return

    machine_sids = _machine_sids_by_machine_id.get(machine_id)
    if not machine_sids:
        return

    machine_sids.discard(sid)
    if not machine_sids:
        _machine_sids_by_machine_id.pop(machine_id, None)


def register_log_stream_subscriber(machine_id: str, sid: str) -> None:
    machine_id = str(machine_id)
    _log_stream_subscribers_by_machine_id.setdefault(machine_id, set()).add(sid)
    _log_stream_machine_ids_by_sid.setdefault(sid, set()).add(machine_id)


def unregister_log_stream_subscriber(machine_id: str, sid: str) -> None:
    machine_id = str(machine_id)
    subscribers = _log_stream_subscribers_by_machine_id.get(machine_id)
    if subscribers:
        subscribers.discard(sid)
        if not subscribers:
            _log_stream_subscribers_by_machine_id.pop(machine_id, None)

    machine_ids = _log_stream_machine_ids_by_sid.get(sid)
    if machine_ids:
        machine_ids.discard(machine_id)
        if not machine_ids:
            _log_stream_machine_ids_by_sid.pop(sid, None)


def unregister_all_log_stream_subscriptions(sid: str) -> None:
    machine_ids = list(_log_stream_machine_ids_by_sid.get(sid, set()))
    for machine_id in machine_ids:
        unregister_log_stream_subscriber(machine_id, sid)


def has_machine_log_stream_subscribers(machine_id: str) -> bool:
    return bool(_log_stream_subscribers_by_machine_id.get(str(machine_id)))


async def emit_machine_log_stream_status(
    machine: dict,
    *,
    room: str | None = None,
    subscribed: bool | None = None,
) -> None:
    machine_id = str(machine["_id"])
    payload = {
        "machine_id": machine_id,
        "machine_online": is_machine_online(machine),
        "stream_requested": has_machine_log_stream_subscribers(machine_id),
    }
    if subscribed is not None:
        payload["subscribed"] = subscribed
    await emit(
        STC_MACHINE_LOG_STREAM_STATUS,
        payload,
        user_id=str(machine["user_id"]),
        room=room,
    )


async def emit_machine_log_lines(
    machine: dict,
    *,
    lines: list[str],
    source: str = "client",
) -> None:
    machine_id = str(machine["_id"])
    room = get_machine_log_room(machine_id)
    if not has_machine_log_stream_subscribers(machine_id):
        return

    for line in lines:
        await sio.emit(
            STC_MACHINE_LOG_STREAM_LINE,
            data=jsonable_encoder(
                {
                    "machine_id": machine_id,
                    "source": source,
                    "line": line,
                }
            ),
            room=room,
        )


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
    await emit_machine_log_stream_status(
        machine,
        room=room or get_machine_log_room(str(machine["_id"])),
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


async def emit_machine_config_snapshot(machine: dict, room: str | None = None) -> None:
    machine_id = str(machine["_id"])
    await sio.emit(
        STC_MACHINE_CONFIG_SNAPSHOT,
        data=jsonable_encoder(
            {
                "machine_id": machine_id,
                "config": await build_machine_config_bundle(machine),
            }
        ),
        room=room or get_machine_room(machine_id),
    )


async def emit_machine_config_changed(machine_id: str, room: str | None = None) -> None:
    machine = await db.machines.find_one({"_id": ObjectId(machine_id)})
    if not machine:
        return
    await sio.emit(
        STC_MACHINE_CONFIG_CHANGED,
        data=jsonable_encoder(
            {
                "machine_id": machine_id,
                "config": await build_machine_config_bundle(machine),
            }
        ),
        room=room or get_machine_room(machine_id),
    )


async def disconnect_machine_clients(machine_id: str) -> None:
    for sid in list(_machine_sids_by_machine_id.get(machine_id, set())):
        await sio.disconnect(sid)
        unregister_machine_sid(sid)


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
        sio.enter_room(sid, user_id)
    elif auth and auth.get("role") == "machine":
        try:
            machine = await authenticate_machine(auth.get("machine_id"), auth.get("token"))
        except Exception:
            return False

        machine_id = str(machine["_id"])
        await sio.save_session(
            sid,
            {
                "role": "machine",
                "machine_id": machine_id,
                "user_id": str(machine["user_id"]),
            },
        )
        sio.enter_room(sid, get_machine_room(machine_id))
        register_machine_sid(machine_id, sid)

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


@sio.on(CTS_MACHINE_CONFIG_SNAPSHOT)
async def handle_machine_config_snapshot(sid, data=None):
    try:
        session = await sio.get_session(sid)
    except KeyError:
        return

    if session.get("role") != "machine":
        return

    machine_id = session.get("machine_id")
    if not machine_id:
        return

    machine = await db.machines.find_one({"_id": ObjectId(machine_id)})
    if not machine:
        return

    await emit_machine_config_snapshot(machine, room=sid)


@sio.on(CTS_MACHINE_LOG_STREAM_SUBSCRIBE)
async def handle_machine_log_stream_subscribe(sid, data=None):
    try:
        session = await sio.get_session(sid)
    except KeyError:
        return

    user_id = session.get("user_id")
    machine_id = (data or {}).get("machine_id")
    if not user_id or not machine_id or not ObjectId.is_valid(machine_id):
        return

    machine = await db.machines.find_one(
        {"_id": ObjectId(machine_id), "user_id": ObjectId(user_id)}
    )
    if not machine:
        return

    sio.enter_room(sid, get_machine_log_room(machine_id))
    register_log_stream_subscriber(machine_id, sid)
    await emit_machine_log_stream_status(machine, room=sid, subscribed=True)


@sio.on(CTS_MACHINE_LOG_STREAM_UNSUBSCRIBE)
async def handle_machine_log_stream_unsubscribe(sid, data=None):
    try:
        session = await sio.get_session(sid)
    except KeyError:
        return

    user_id = session.get("user_id")
    machine_id = (data or {}).get("machine_id")
    if not user_id or not machine_id or not ObjectId.is_valid(machine_id):
        return

    machine = await db.machines.find_one(
        {"_id": ObjectId(machine_id), "user_id": ObjectId(user_id)}
    )
    if not machine:
        return

    sio.leave_room(sid, get_machine_log_room(machine_id))
    unregister_log_stream_subscriber(machine_id, sid)
    await emit_machine_log_stream_status(machine, room=sid, subscribed=False)


@sio.event
async def disconnect(sid):
    unregister_machine_sid(sid)
    unregister_all_log_stream_subscriptions(sid)
    return None
