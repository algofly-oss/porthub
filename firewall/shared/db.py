import json

import aiosqlite

from .env import DB_PATH


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS port_policies (
                port INTEGER PRIMARY KEY,
                is_public INTEGER NOT NULL DEFAULT 1,
                allowed_ips TEXT NOT NULL DEFAULT '[]',
                updated_at INTEGER NOT NULL
            )
            """
        )

        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_buffer (
                port INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                in_bytes INTEGER NOT NULL,
                out_bytes INTEGER NOT NULL
            )
            """
        )

        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS active_ports (
                port INTEGER PRIMARY KEY,
                last_seen INTEGER NOT NULL
            )
            """
        )

        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS recent_ip_hits (
                port INTEGER NOT NULL,
                ip TEXT NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (port, ip)
            )
            """
        )

        # Compatibility with the original sample schema.
        cursor = await db.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'allowlists'
            """
        )
        allowlists_table = await cursor.fetchone()
        await cursor.close()
        if allowlists_table:
            await db.execute(
                """
                INSERT OR IGNORE INTO port_policies (port, is_public, allowed_ips, updated_at)
                SELECT port, 0, ips, strftime('%s', 'now')
                FROM allowlists
                """
            )

        await db.commit()


async def load_state() -> dict[str, dict]:
    state: dict[str, dict] = {}
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT port, is_public, allowed_ips
            FROM port_policies
            ORDER BY port ASC
            """
        )
        rows = await cursor.fetchall()
        await cursor.close()

    for port, is_public, allowed_ips in rows:
        state[str(port)] = {
            "is_public": bool(is_public),
            "allowed_ips": json.loads(allowed_ips or "[]"),
        }

    return state
