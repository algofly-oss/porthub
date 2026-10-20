"""Incremental, privacy-minimal request counts from Traefik's existing JSON log.

The first run starts at EOF: historical logs can be many gigabytes. Counts are
explicitly since tracking began. Totals and the read checkpoint share one atomic
Mongo document, so restarts/multiple API workers cannot double-count a batch.
"""
import asyncio
import copy
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from shared.factory import db

logger = logging.getLogger(__name__)
STATE_ID = "traefik-requests-v1"
LOG_PATH = Path(os.environ.get("PROXY_ACCESS_LOG_PATH", "/runtime/traefik-access/access.log"))
MAX_BATCH_BYTES = 2 * 1024 * 1024


def read_batch(path, checkpoint):
    try:
        with Path(path).open("rb") as log:
            stat = os.fstat(log.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"
            if checkpoint is None:
                return identity, stat.st_size, []
            if checkpoint["identity"] != identity:
                rotated = Path(str(path) + ".1")
                try:
                    rotated_stat = rotated.stat()
                    rotated_identity = f"{rotated_stat.st_dev}:{rotated_stat.st_ino}"
                    if rotated_identity == checkpoint["identity"] and rotated_stat.st_size > checkpoint["offset"]:
                        return read_batch(rotated, checkpoint)
                except FileNotFoundError:
                    pass
            offset = checkpoint["offset"] if checkpoint["identity"] == identity and checkpoint["offset"] <= stat.st_size else 0
            log.seek(offset)
            chunk = log.read(MAX_BATCH_BYTES)
            end = chunk.rfind(b"\n") + 1
            if not end:
                # Leave an incomplete final line for the next read. A malformed
                # oversized line cannot pin the reader indefinitely.
                return identity, offset + (len(chunk) if len(chunk) == MAX_BATCH_BYTES else 0), []
            records = []
            for line in chunk[:end].splitlines():
                try:
                    record = json.loads(line)
                    host = str(record.get("RequestHost", "")).lower().split(":", 1)[0].rstrip(".")
                    stamp = str(record.get("StartUTC", "")).replace("Z", "+00:00")
                    # Go emits RFC3339 nanoseconds; Python 3.10's parser only
                    # accepts three or six fractional digits.
                    stamp = re.sub(r"\.(\d+)", lambda match: "."+match[1][:6].ljust(6,"0"), stamp)
                    timestamp = datetime.fromisoformat(stamp)
                    if timestamp.tzinfo is None or not record.get("RouterName"):
                        continue
                    records.append((host, timestamp.astimezone(timezone.utc).isoformat()))
                except (ValueError, TypeError, AttributeError):
                    continue
            return identity, offset + end, records
    except FileNotFoundError:
        return None


def apply_records(metrics, records, routes):
    # Map only registered hosts. Never persist IPs, paths, queries, identities,
    # arbitrary Host headers, or raw log records.
    by_host = {host.lower(): str(route["_id"]) for route in routes for host in route.get("hosts", [])}
    valid_ids = {str(route["_id"]) for route in routes}
    result = {key: copy.deepcopy(value) for key, value in metrics.items() if key in valid_ids}
    for host, timestamp in records:
        route_id = by_host.get(host)
        if not route_id:
            continue
        metric = result.setdefault(route_id, {"requests": 0, "last_requested_at": None})
        metric["requests"] += 1
        if not metric["last_requested_at"] or timestamp > metric["last_requested_at"]:
            metric.update(last_requested_at=timestamp, last_host=host)
    return result


def previous_segment_available(path, identity, offset):
    try:
        stat = Path(str(path)+".1").stat()
        return f"{stat.st_dev}:{stat.st_ino}" == identity and offset <= stat.st_size
    except FileNotFoundError:
        return False


async def collect_proxy_activity():
    state = await db.proxy_activity.find_one({"_id": STATE_ID})
    batch = await asyncio.to_thread(read_batch, LOG_PATH, state)
    if batch is None:
        return
    identity, offset, records = batch
    now = datetime.now(timezone.utc).isoformat()
    if state is None:
        await db.proxy_activity.update_one({"_id": STATE_ID}, {"$setOnInsert": {
            "identity": identity, "offset": offset, "revision": 0,
            "tracking_since": now, "updated_at": now, "metrics": {},
        }}, upsert=True)
        return
    if identity == state["identity"] and offset == state["offset"]:
        return
    routes = await db.traffic_routes.find({}, {"_id": 1, "hosts": 1}).to_list(None)
    metrics = apply_records(state.get("metrics", {}), records, routes)
    gap = identity == state["identity"] and offset < state["offset"]
    if identity != state["identity"]:
        gap = not await asyncio.to_thread(previous_segment_available, LOG_PATH, state["identity"], state["offset"])
    await db.proxy_activity.update_one({"_id": STATE_ID, "revision": state["revision"]}, {"$set": {
        "identity": identity, "offset": offset, "metrics": metrics, "updated_at": now,
        "coverage_warning": bool(state.get("coverage_warning") or gap),
    }, "$inc": {"revision": 1}})


async def monitor_proxy_activity():
    while True:
        try:
            await collect_proxy_activity()
        except Exception:
            logger.exception("Proxy request analytics could not read its next batch")
        await asyncio.sleep(5)
