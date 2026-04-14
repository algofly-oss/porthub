import json
import time

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException

from router.auth import require_key
from shared.env import DB_PATH
from shared.nft import apply_rules
from shared.state import STATE
from .models.policy import PortPolicyRequest

router = APIRouter()


def _serialize_policy(port: int, config: dict | None) -> dict:
    effective = config or {"is_public": True, "allowed_ips": []}
    return {
        "port": port,
        "is_public": bool(effective.get("is_public", True)),
        "allowed_ips": list(effective.get("allowed_ips") or []),
    }


@router.get("/{port}/policy", dependencies=[Depends(require_key)])
async def get_port_policy(port: int):
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port")

    return {
        "msg": "Port policy fetched successfully",
        "data": _serialize_policy(port, STATE.get(str(port))),
    }


@router.put("/{port}/policy", dependencies=[Depends(require_key)])
async def update_port_policy(port: int, data: PortPolicyRequest):
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port")

    config = {
        "is_public": data.is_public,
        "allowed_ips": [str(ip) for ip in data.allowed_ips],
    }

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO port_policies (port, is_public, allowed_ips, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (port, 1 if data.is_public else 0, json.dumps(config["allowed_ips"]), int(time.time())),
        )
        await db.commit()

    STATE[str(port)] = config
    apply_rules(STATE)

    return {
        "msg": "Port policy updated successfully",
        "data": _serialize_policy(port, config),
    }


@router.delete("/{port}/policy", dependencies=[Depends(require_key)])
async def delete_port_policy(port: int):
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port")

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM port_policies WHERE port = ?", (port,))
        await db.commit()

    STATE.pop(str(port), None)
    apply_rules(STATE)

    return {
        "msg": "Port policy deleted successfully",
        "data": _serialize_policy(port, None),
    }


@router.get("/policies/list", dependencies=[Depends(require_key)])
async def list_port_policies():
    return {
        "msg": "Port policies listed successfully",
        "data": [
            _serialize_policy(int(port), config)
            for port, config in sorted(STATE.items(), key=lambda item: int(item[0]))
        ],
    }
