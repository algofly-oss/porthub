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


def record_snapshot(data: dict, now: int, sampled_at: float) -> None:
    counters = {}
    sets_by_name = {obj["set"].get("name"): {"nftables": [obj]} for obj in data.get("nftables", []) if "set" in obj}
    for obj in data.get("nftables", []):
        counter = obj.get("counter") or {}
        name = counter.get("name", "")
        for direction in ("in", "out", "drop"):
            prefix = f"cnt_{direction}_"
            if not name.startswith(prefix):
                continue
            try:
                port = int(name[len(prefix):])
                value = max(0, int(counter.get("bytes", 0)))
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                counters.setdefault(port, {})[direction] = value

    for port, values in counters.items():
        stat = PORT_STATS[port]
        previous_time = stat["sampled_at"]
        duration = max(0.001, sampled_at - previous_time) if previous_time is not None else 0
        deltas = {}
        for direction in ("in", "out", "drop"):
            key = f"last_{direction}"
            value = values.get(direction, stat[key])
            previous = stat[key]
            # First observation establishes a baseline. Counter resets start a
            # new baseline too; lifetime bytes must never become a fresh spike.
            deltas[direction] = max(0, value - previous) if previous is not None and value is not None else 0
            stat[key] = value
        stat["sampled_at"] = sampled_at
        if previous_time is None:
            continue

        source_hits = _list_source_ip_hits_for_set(f"recent_{port}", payload=sets_by_name.get(f"recent_{port}", {}), observed_at=now)
        stat["recent_hits"] = source_hits
        ips = {}
        for direction, set_name in (("in", f"recent_{port}"), ("out", f"recent_out_{port}"), ("drop", f"blocked_{port}")):
            hits = source_hits if direction == "in" else _list_source_ip_hits_for_set(set_name, payload=sets_by_name.get(set_name, {}), observed_at=now)
            ips[direction] = [str(item["ip"]) for item in hits
                              if int(item["last_seen"]) >= now - max(2, duration + 1)] if deltas[direction] else []
        sample = {"timestamp": now, "interval_seconds": duration,
                  "in_bytes": deltas["in"], "out_bytes": deltas["out"], "drop_bytes": deltas["drop"],
                  "incoming_ips": ips["in"], "outgoing_ips": ips["out"], "blocked_ips": ips["drop"]}
        if stat["history"] and stat["history"][-1]["timestamp"] == now:
            previous_sample = stat["history"][-1]
            for key in ("in_bytes", "out_bytes", "drop_bytes", "interval_seconds"):
                previous_sample[key] += sample[key]
            for key in ("incoming_ips", "outgoing_ips", "blocked_ips"):
                previous_sample[key] = sorted(set(previous_sample[key] + sample[key]))
        else:
            stat["history"].append(sample)
        if any(deltas.values()):
            ACTIVE_PORTS[port] = now
            pending.append((port, now, deltas["in"], deltas["out"], deltas["drop"],
                            json.dumps(ips["drop"]), json.dumps(ips["in"]), json.dumps(ips["out"])))

    # Only a successfully observed removal may discard a counter baseline.
    for port in set(PORT_STATS) - set(counters):
        PORT_STATS.pop(port, None)
        ACTIVE_PORTS.pop(port, None)
    cleanup_ports(now)


async def traffic_loop():
    while True:
        started = time.monotonic()
        try:
            raw = await asyncio.to_thread(subprocess.check_output,
                ["nft", "-j", "list", "table", *NFT_TABLE.split()], text=True)
            record_snapshot(json.loads(raw), int(time.time()), time.monotonic())
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
            pass
        await asyncio.sleep(max(0.05, 1 - (time.monotonic() - started)))


def cleanup_ports(now: int) -> None:
    for port, last_seen in list(ACTIVE_PORTS.items()):
        if now - last_seen > ACTIVE_TTL:
            ACTIVE_PORTS.pop(port, None)
    # Idle ports keep their last counters; dropping them causes historical
    # cumulative bytes to be reported again when traffic resumes.
    for stat in PORT_STATS.values():
        while stat["history"] and stat["history"][0]["timestamp"] < now - BUFFER_SECONDS:
            stat["history"].popleft()


def _list_source_ip_hits_for_set(set_name: str, payload=None, observed_at=None) -> list[dict[str, int | str]]:
    if payload is None:
        try:
            output = subprocess.check_output(
                ["nft", "-j", "list", "set", *NFT_TABLE.split(), set_name],
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
    now = int(time.time()) if observed_at is None else observed_at
    for item in payload.get("nftables", []):
        set_payload = item.get("set")
        if not set_payload or set_payload.get("name") != set_name:
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


def list_recent_source_ip_hits(port: int) -> list[dict[str, int | str]]:
    return _list_source_ip_hits_for_set(f"recent_{port}")


def list_recent_destination_ip_hits(port: int) -> list[dict[str, int | str]]:
    return _list_source_ip_hits_for_set(f"recent_out_{port}")


def list_blocked_source_ip_hits(port: int) -> list[dict[str, int | str]]:
    return _list_source_ip_hits_for_set(f"blocked_{port}")


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
        tracked_ports = {port for port, _, _, _, _, _, _, _ in batch}
        recent_hits = []
        for port in tracked_ports:
            for item in PORT_STATS.get(port, {}).get("recent_hits", []):
                recent_hits.append((port, item["ip"], item["last_seen"]))

        async with aiosqlite.connect(DB_PATH) as db:
            await db.executemany(
                """
                INSERT INTO traffic_buffer (
                    port,
                    ts,
                    in_bytes,
                    out_bytes,
                    drop_bytes,
                    blocked_ips,
                    incoming_ips,
                    outgoing_ips
                )
                VALUES (?,?,?,?,?,?,?,?)
                """,
                batch,
            )
            await db.executemany(
                "INSERT OR REPLACE INTO active_ports (port, last_seen) VALUES (?, ?)",
                [(port, timestamp) for port, timestamp, _, _, _, _, _, _ in batch],
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
