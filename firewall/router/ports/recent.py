import aiosqlite
from fastapi import APIRouter, Depends, Query

from router.auth import require_key
from shared.env import DB_PATH
from shared.sampler import list_recent_source_ip_hits, trim_recent_ip_history

router = APIRouter()


@router.get("/{port}/recent-ip-hits", dependencies=[Depends(require_key)])
async def get_recent_ip_hits(port: int, limit: int = Query(10, ge=1, le=50)):
    live_hits = list_recent_source_ip_hits(port)

    async with aiosqlite.connect(DB_PATH) as db:
        if live_hits:
            await db.executemany(
                """
                INSERT INTO recent_ip_hits (port, ip, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(port, ip) DO UPDATE SET last_seen = excluded.last_seen
                """,
                [(port, str(item["ip"]), int(item["last_seen"])) for item in live_hits],
            )
            await trim_recent_ip_history(db, port)
            await db.commit()

        cursor = await db.execute(
            """
            SELECT ip, last_seen
            FROM recent_ip_hits
            WHERE port = ?
            ORDER BY last_seen DESC, ip ASC
            LIMIT ?
            """,
            (port, limit),
        )
        rows = await cursor.fetchall()

    return {
        "msg": "Recent IP hits fetched successfully",
        "data": [
            {"ip": ip, "last_seen": last_seen}
            for ip, last_seen in rows
        ],
    }
