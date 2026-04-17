import asyncio
import time

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from router.auth import require_key
from shared.env import BUFFER_SECONDS
from shared.state import PORT_STATS
from .models.traffic import TrafficSnapshotRequest

router = APIRouter()


@router.post("/traffic/snapshot", dependencies=[Depends(require_key)])
async def snapshot(data: TrafficSnapshotRequest):
    cutoff = int(time.time()) - BUFFER_SECONDS
    response = {}

    for port in data.ports:
        stat = PORT_STATS.get(port)
        if not stat:
            response[port] = []
            continue

        response[port] = [
            {
                "timestamp": ts,
                "in_bytes": in_bytes,
                "out_bytes": out_bytes,
                "drop_bytes": drop_bytes,
                "blocked_ips": blocked_ips,
                "incoming_ips": incoming_ips,
                "outgoing_ips": outgoing_ips,
            }
            for (
                ts,
                in_bytes,
                out_bytes,
                drop_bytes,
                blocked_ips,
                incoming_ips,
                outgoing_ips,
            ) in stat["history"]
            if ts >= cutoff
        ]

    return {
        "msg": "Traffic snapshot fetched successfully",
        "data": response,
    }


@router.websocket("/traffic/ws")
async def ws_traffic(ws: WebSocket):
    await ws.accept()

    try:
        while True:
            payload = {}
            cutoff = int(time.time()) - BUFFER_SECONDS

            for port, stat in PORT_STATS.items():
                if not stat["history"]:
                    continue

                (
                    ts,
                    in_bytes,
                    out_bytes,
                    drop_bytes,
                    blocked_ips,
                    incoming_ips,
                    outgoing_ips,
                ) = stat["history"][-1]
                if ts < cutoff:
                    continue

                payload[port] = {
                    "timestamp": ts,
                    "in_bytes": in_bytes,
                    "out_bytes": out_bytes,
                    "drop_bytes": drop_bytes,
                    "blocked_ips": blocked_ips,
                    "incoming_ips": incoming_ips,
                    "outgoing_ips": outgoing_ips,
                }

            if payload:
                await ws.send_json(payload)

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
