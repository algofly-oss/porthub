"""Login sessions and background leases stored in MongoDB.

Sessions survive API restarts and deploys (Redis kept them only in memory).
A session lasts SESSION_DAYS and is renewed at most once a day while used, so
active browsers and installed home-screen apps stay signed in; revoking a
session (sign out, device list, account deletion) takes effect immediately.
"""
import datetime
import json
import uuid

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from shared.env import SESSION_COOKIE_NAME
from shared.factory import db

SESSION_DAYS = 180
RENEW_AFTER = datetime.timedelta(days=1)


def utcnow():
    return datetime.datetime.utcnow()


def is_https(request):
    """True when the browser reached us over HTTPS, including via Cloudflare
    or a TLS-terminating proxy that forwards plain HTTP."""
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https":
        return True
    try:
        return json.loads(request.headers.get("cf-visitor", "{}")).get("scheme") == "https"
    except ValueError:
        return False


def set_session_cookie(response, request, token):
    response.set_cookie(
        key=SESSION_COOKIE_NAME, value=token, max_age=SESSION_DAYS * 86400,
        httponly=True, samesite="lax", secure=is_https(request),
    )


async def session_user_id(token):
    """User id string for a valid session token, or None."""
    if not token or not isinstance(token, str) or len(token) > 128:
        return None
    session = await db.user_sessions.find_one(
        {"_id": token, "revoked_at": None}, {"user_id": 1, "expires_at": 1}
    )
    if not session:
        return None
    expires = session.get("expires_at")
    if expires and expires <= utcnow():
        return None
    return str(session["user_id"])


async def start_session(user_id, request, response):
    from router.auth.session_utils import create_session_record

    token = str(uuid.uuid4())
    await create_session_record(db, user_id, token, request)
    await db.user_sessions.update_one(
        {"_id": token},
        {"$set": {"expires_at": utcnow() + datetime.timedelta(days=SESSION_DAYS), "renewed_at": utcnow()}},
    )
    set_session_cookie(response, request, token)
    return token


async def revoke_session(token):
    if token:
        await db.user_sessions.update_one({"_id": token}, {"$set": {"revoked_at": utcnow()}})


async def revoke_user_sessions(user_id):
    await db.user_sessions.update_many(
        {"user_id": str(user_id), "revoked_at": None}, {"$set": {"revoked_at": utcnow()}}
    )


async def renew_if_due(token, request, response):
    """Slide the expiry forward at most once a day for an active session."""
    if not token or len(token) > 128:
        return
    now = utcnow()
    renewed = await db.user_sessions.find_one_and_update(
        {
            "_id": token, "revoked_at": None,
            "$and": [
                {"$or": [{"expires_at": None}, {"expires_at": {"$exists": False}}, {"expires_at": {"$gt": now}}]},
                {"$or": [{"renewed_at": {"$exists": False}}, {"renewed_at": {"$lt": now - RENEW_AFTER}}]},
            ],
        },
        {"$set": {"renewed_at": now, "expires_at": now + datetime.timedelta(days=SESSION_DAYS)}},
        projection={"_id": 1}, return_document=ReturnDocument.AFTER,
    )
    if renewed:
        set_session_cookie(response, request, token)


async def hold_lease(name, holder, ttl_seconds):
    """Single-holder lease shared by all API workers (replaces a Redis key)."""
    now = utcnow()
    expires = now + datetime.timedelta(seconds=ttl_seconds)
    try:
        lease = await db.leases.find_one_and_update(
            {"_id": name, "$or": [{"holder": holder}, {"expires_at": {"$lte": now}}]},
            {"$set": {"holder": holder, "expires_at": expires}},
            upsert=True, return_document=ReturnDocument.AFTER,
        )
        return bool(lease and lease.get("holder") == holder)
    except DuplicateKeyError:
        return False  # another worker holds an unexpired lease
