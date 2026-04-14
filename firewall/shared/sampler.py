import asyncio
import json
import subprocess
import time

import aiosqlite

from .env import (
    ACTIVE_TTL,
    BUFFER_SECONDS,
    DB_PATH,
    NFT_TABLE,
    RECENT_IP_HISTORY_LIMIT,
)
from .state import ACTIVE_PORTS, PORT_STATS

pending = []


async def traffic_loop():
    while True:
        try:
            raw = subprocess.check_output(
                ["nft", "-j", "list", "table", *NFT_TABLE.split()],
                text=True,
            )
            data = json.loads(raw)
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
            await asyncio.sleep(1)
            continue

        now = int(time.time())

        for obj in data.get("nftables", []):
            counter = obj.get("counter")
            if not counter:
                continue

            name = counter.get("name") or ""
            bytes_value = int(counter.get("bytes", 0))

            if name.startswith("cnt_in_"):
                port = int(name.split("_")[-1])
                stat = PORT_STATS[port]
                delta = max(0, bytes_value - stat["last_in"])
                stat["last_in"] = bytes_value
                if delta > 0:
                    stat["history"].append((now, delta, 0))
                    ACTIVE_PORTS[port] = now
                    pending.append((port, now, delta, 0))
                continue

            if name.startswith("cnt_out_"):
                port = int(name.split("_")[-1])
                stat = PORT_STATS[port]
                delta = max(0, bytes_value - stat["last_out"])
                stat["last_out"] = bytes_value
                if delta > 0:
                    stat["history"].append((now, 0, delta))
                    ACTIVE_PORTS[port] = now
                    pending.append((port, now, 0, delta))

        cleanup_ports(now)
        await asyncio.sleep(1)


def cleanup_ports(now: int) -> None:
    for port, last_seen in list(ACTIVE_PORTS.items()):
        if now - last_seen > ACTIVE_TTL:
            ACTIVE_PORTS.pop(port, None)
            PORT_STATS.pop(port, None)


def list_recent_source_ip_hits(port: int) -> list[dict[str, int | str]]:
    try:
        output = subprocess.check_output(
            ["nft", "-j", "list", "set", *NFT_TABLE.split(), f"recent_{port}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        payload = json.loads(output)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        return []

    def _extract_hit(value):
        if isinstance(value, str):
            ip = value.strip()
            return {"ip": ip, "timeout": None, "expires": None} if ip else None

        if not isinstance(value, dict):
            return None

        if "elem" in value:
            return _extract_hit(value["elem"])

        ip = value.get("val")
        if not isinstance(ip, str) or not ip.strip():
            return None

        timeout = value.get("timeout")
        expires = value.get("expires")
        return {
            "ip": ip.strip(),
            "timeout": int(timeout) if isinstance(timeout, (int, float)) else None,
            "expires": int(expires) if isinstance(expires, (int, float)) else None,
        }

    seen: list[dict[str, int | str]] = []
    seen_ips: set[str] = set()
    now = int(time.time())
    for item in payload.get("nftables", []):
        set_payload = item.get("set")
        if not set_payload:
            continue

        elements = set_payload.get("elem") or []
        for element in elements:
            hit = _extract_hit(element)
            if not hit:
                continue

            ip = str(hit["ip"])
            timeout = hit.get("timeout")
            expires = hit.get("expires")
            if isinstance(timeout, int) and isinstance(expires, int):
                last_seen = now - max(0, timeout - expires)
            else:
                last_seen = now

            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                seen.append({"ip": ip, "last_seen": last_seen})

    seen.sort(key=lambda item: (-int(item["last_seen"]), str(item["ip"])))
    return seen


def list_recent_source_ips(port: int) -> list[str]:
    return [str(item["ip"]) for item in list_recent_source_ip_hits(port)]


async def trim_recent_ip_history(db: aiosqlite.Connection, port: int) -> None:
    await db.execute(
        """
        DELETE FROM recent_ip_hits
        WHERE rowid IN (
            SELECT rowid
            FROM recent_ip_hits
            WHERE port = ?
            ORDER BY last_seen DESC, ip ASC
            LIMIT -1 OFFSET ?
        )
        """,
        (port, RECENT_IP_HISTORY_LIMIT),
    )


async def db_writer():
    while True:
        if not pending:
            await asyncio.sleep(1)
            continue

        batch = pending[:]
        pending.clear()
        prune_before = int(time.time()) - BUFFER_SECONDS
        tracked_ports = {port for port, _, _, _ in batch}
        recent_hits = []
        for port in tracked_ports:
            for item in list_recent_source_ip_hits(port):
                recent_hits.append((port, item["ip"], item["last_seen"]))

        async with aiosqlite.connect(DB_PATH) as db:
            await db.executemany(
                "INSERT INTO traffic_buffer (port, ts, in_bytes, out_bytes) VALUES (?,?,?,?)",
                batch,
            )
            await db.executemany(
                "INSERT OR REPLACE INTO active_ports (port, last_seen) VALUES (?, ?)",
                [(port, timestamp) for port, timestamp, _, _ in batch],
            )
            if recent_hits:
                await db.executemany(
                    """
                    INSERT INTO recent_ip_hits (port, ip, last_seen)
                    VALUES (?, ?, ?)
                    ON CONFLICT(port, ip) DO UPDATE SET last_seen = excluded.last_seen
                    """,
                    recent_hits,
                )
                for port in tracked_ports:
                    await trim_recent_ip_history(db, port)
            await db.execute("DELETE FROM traffic_buffer WHERE ts < ?", (prune_before,))
            await db.execute("DELETE FROM active_ports WHERE last_seen < ?", (prune_before,))
            await db.commit()

        await asyncio.sleep(5)
