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

        response[port] = [sample for sample in stat["history"] if sample["timestamp"] >= cutoff]

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

                sample = stat["history"][-1]
                if sample["timestamp"] < cutoff:
                    continue

                payload[port] = sample

            if payload:
                await ws.send_json(payload)

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
