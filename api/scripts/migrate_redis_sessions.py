"""One-time move of login sessions from Redis to MongoDB (run before the
Redis container is removed). Live Redis sessions become active Mongo
sessions; Mongo sessions with no live Redis key are marked revoked, so the
result matches exactly what was valid before. Re-running is harmless.

Usage (inside the API container): python scripts/migrate_redis_sessions.py
"""
import asyncio
import datetime
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from redis import Redis  # noqa: E402

from shared.factory import db  # noqa: E402

TOKEN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
USER = re.compile(r"[0-9a-f]{24}\Z")


async def main():
    redis = Redis(host=os.environ["REDIS_HOST"], port=int(os.environ.get("REDIS_PORT", 6379)), password=os.environ.get("REDIS_PASSWORD") or None)
    now = datetime.datetime.utcnow()
    live = {}
    for key in redis.scan_iter(count=500):
        token = key.decode(errors="ignore")
        value = (redis.get(key) or b"").decode(errors="ignore")
        if TOKEN.fullmatch(token) and USER.fullmatch(value):
            live[token] = value
    created = kept = 0
    for token, user_id in live.items():
        existing = await db.user_sessions.find_one({"_id": token})
        if existing:
            kept += 1  # an explicit revocation in Mongo is respected
            continue
        await db.user_sessions.insert_one({"_id": token, "token": token, "user_id": user_id, "created_at": now,
                                           "last_accessed_at": now, "revoked_at": None, "migrated_from_redis": True})
        created += 1
    stale = await db.user_sessions.update_many(
        {"revoked_at": None, "_id": {"$nin": list(live)}}, {"$set": {"revoked_at": now, "revoked_reason": "not live in redis at migration"}})
    print(f"live redis sessions {len(live)}; created in mongo {created}; already present {kept}; stale mongo sessions revoked {stale.modified_count}")


asyncio.get_event_loop().run_until_complete(main())
