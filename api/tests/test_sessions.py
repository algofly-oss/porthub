"""Mongo-backed sessions and leases against an isolated, dropped database."""
import datetime
import secrets
import unittest
from unittest.mock import patch

from fastapi import Response
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.requests import Request

from shared import sessions
from shared.env import MONGO_DATABASE_URI, SESSION_COOKIE_NAME


def request(headers=()):
    return Request({"type": "http", "method": "POST", "path": "/", "scheme": "http", "query_string": b"",
                    "headers": [(k.encode(), v.encode()) for k, v in headers], "client": ("127.0.0.1", 1), "server": ("x", 80)})


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = AsyncIOMotorClient(MONGO_DATABASE_URI, serverSelectionTimeoutMS=3000)
        self.name = "porthub_session_tests_" + secrets.token_hex(8)
        self.db = self.client[self.name]
        self.patch = patch.object(sessions, "db", self.db)
        self.patch.start()
        import router.auth.session_utils  # noqa: F401  (start_session imports it)

    async def asyncTearDown(self):
        self.patch.stop()
        assert self.name.startswith("porthub_session_tests_")
        await self.client.drop_database(self.name)
        self.client.close()

    async def test_persistent_session_lifecycle(self):
        response = Response()
        token = await sessions.start_session("u1", request(), response)
        cookie = response.headers["set-cookie"]
        self.assertIn(f"{SESSION_COOKIE_NAME}={token}", cookie)
        self.assertIn(f"Max-Age={sessions.SESSION_DAYS * 86400}", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertNotIn("Secure", cookie)  # plain HTTP access keeps working
        self.assertEqual(await sessions.session_user_id(token), "u1")
        self.assertIsNone(await sessions.session_user_id("not-a-session"))
        self.assertIsNone(await sessions.session_user_id(None))
        await sessions.revoke_session(token)
        self.assertIsNone(await sessions.session_user_id(token))

    async def test_https_behind_cloudflare_sets_secure_cookie(self):
        response = Response()
        await sessions.start_session("u1", request([("cf-visitor", '{"scheme":"https"}')]), response)
        self.assertIn("Secure", response.headers["set-cookie"])

    async def test_expiry_and_daily_renewal(self):
        token = await sessions.start_session("u1", request(), Response())
        response = Response()
        await sessions.renew_if_due(token, request(), response)
        self.assertNotIn("set-cookie", response.headers)  # renewed less than a day ago
        old = datetime.datetime.utcnow() - datetime.timedelta(days=2)
        await self.db.user_sessions.update_one({"_id": token}, {"$set": {"renewed_at": old, "expires_at": old + datetime.timedelta(days=5)}})
        await sessions.renew_if_due(token, request(), response)
        self.assertIn("set-cookie", response.headers)
        stored = await self.db.user_sessions.find_one({"_id": token})
        self.assertGreater(stored["expires_at"], datetime.datetime.utcnow() + datetime.timedelta(days=sessions.SESSION_DAYS - 1))
        await self.db.user_sessions.update_one({"_id": token}, {"$set": {"expires_at": old}})
        self.assertIsNone(await sessions.session_user_id(token))
        expired = Response()
        await sessions.renew_if_due(token, request(), expired)
        self.assertNotIn("set-cookie", expired.headers)  # an expired session is never revived

    async def test_legacy_sessions_without_expiry_stay_valid_and_get_one(self):
        await self.db.user_sessions.insert_one({"_id": "legacy", "user_id": "u2", "revoked_at": None})
        self.assertEqual(await sessions.session_user_id("legacy"), "u2")
        await sessions.renew_if_due("legacy", request(), Response())
        self.assertIn("expires_at", await self.db.user_sessions.find_one({"_id": "legacy"}))

    async def test_revoke_all_user_sessions(self):
        a = await sessions.start_session("u1", request(), Response())
        b = await sessions.start_session("u1", request(), Response())
        other = await sessions.start_session("u2", request(), Response())
        await sessions.revoke_user_sessions("u1")
        self.assertIsNone(await sessions.session_user_id(a))
        self.assertIsNone(await sessions.session_user_id(b))
        self.assertEqual(await sessions.session_user_id(other), "u2")

    async def test_lease_has_a_single_holder(self):
        self.assertTrue(await sessions.hold_lease("monitor", "w1", 30))
        self.assertFalse(await sessions.hold_lease("monitor", "w2", 30))
        self.assertTrue(await sessions.hold_lease("monitor", "w1", 30))  # renewal
        await self.db.leases.update_one({"_id": "monitor"}, {"$set": {"expires_at": datetime.datetime.utcnow() - datetime.timedelta(seconds=1)}})
        self.assertTrue(await sessions.hold_lease("monitor", "w2", 30))  # takeover after expiry
