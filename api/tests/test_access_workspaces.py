"""Integration tests use a fresh, isolated database, never application records."""

import asyncio
import secrets
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from bson import ObjectId
from fastapi import HTTPException, Response
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.requests import Request

from router import access
from router.auth import signup
from router.auth.common import UserSignupDto
from shared import workspaces
from shared.env import MONGO_DATABASE_URI
from shared.access_policy import RuleBook, Selector


def request(workspace=None):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": f"workspace={workspace}".encode() if workspace else b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
        }
    )


class AccessWorkspaceTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = AsyncIOMotorClient(
            MONGO_DATABASE_URI, serverSelectionTimeoutMS=3000
        )
        self.name = "porthub_access_tests_" + secrets.token_hex(8)
        self.db = self.client[self.name]
        self.owner, self.alice, self.other = [ObjectId() for _ in range(3)]
        await self.db.users.insert_many(
            [
                {
                    "_id": self.owner,
                    "name": "Owner",
                    "username": "owner@example.test",
                    "role": "user",
                },
                {
                    "_id": self.alice,
                    "name": "Alice",
                    "username": "alice@example.test",
                    "role": "user",
                },
                # Platform administrator deliberately has no workspace membership.
                {
                    "_id": self.other,
                    "name": "Other",
                    "username": "other@example.test",
                    "role": "admin",
                },
            ]
        )
        self.dev, self.prod = ObjectId(), ObjectId()
        await self.db.machine_groups.insert_many(
            [
                {"_id": self.dev, "user_id": self.owner, "name": "Dev"},
                {"_id": self.prod, "user_id": self.owner, "name": "Production"},
            ]
        )
        self.a, self.b = ObjectId(), ObjectId()
        await self.db.machines.insert_many(
            [
                {
                    "_id": self.a,
                    "user_id": self.owner,
                    "name": "Laptop",
                    "group_ids": [self.dev],
                    "token": "TOP-SECRET",
                    "log_tokens": ["SECRET"],
                },
                {
                    "_id": self.b,
                    "user_id": self.owner,
                    "name": "Server",
                    "group_id": self.prod,
                    "token": "TOP-SECRET",
                },
            ]
        )
        self.patches = [
            patch.object(access, "db", self.db),
            patch.object(access.private, "db", self.db),
            patch.object(workspaces, "db", self.db),
            patch.object(
                access,
                "get_authenticated_user",
                AsyncMock(return_value={"_id": self.owner}),
            ),
        ]
        for item in self.patches:
            item.start()

    async def asyncTearDown(self):
        for item in reversed(self.patches):
            item.stop()
        assert (
            self.name.startswith("porthub_access_tests_")
            and len(self.name) == len("porthub_access_tests_") + 16
        )
        await self.client.drop_database(self.name)
        self.client.close()

    def book(self, **changes):
        return RuleBook(
            name="Developer SSH",
            group_id=str(self.dev),
            rules=[
                {
                    "id": "ssh",
                    "name": "Laptop to production SSH",
                    "sources": [{"kind": "group", "id": str(self.dev)}],
                    "destinations": [{"kind": "machine", "id": str(self.b)}],
                    "protocol": "tcp",
                    "ports": "22",
                }
            ],
            **changes,
        )

    async def member(self, role="member"):
        await self.db.workspace_members.insert_one(
            {
                "_id": f"{self.owner}:{self.alice}",
                "workspace_id": self.owner,
                "user_id": self.alice,
                "role": role,
            }
        )

    async def test_owner_implicit_but_global_admin_cannot_enter_other_workspace(self):
        self.assertEqual(
            await workspaces.workspace_access({"_id": self.owner}),
            (self.owner, "owner"),
        )
        with self.assertRaises(HTTPException) as rejected:
            await workspaces.workspace_access(
                {"_id": self.other, "role": "admin"}, str(self.owner)
            )
        self.assertEqual(rejected.exception.status_code, 403)

    async def test_member_read_is_redacted_and_cannot_write(self):
        await self.member()
        with patch.object(
            access,
            "get_authenticated_user",
            AsyncMock(return_value={"_id": self.alice}),
        ):
            state = await access.snapshot(request(self.owner))
            self.assertEqual(state["role"], "member")
            self.assertNotIn("TOP-SECRET", str(state))
            self.assertFalse(state["transport_ready"])
            self.assertEqual(state["books"], [])
            with self.assertRaises(HTTPException) as rejected:
                await access.create_book(self.book(), request(self.owner))
            self.assertEqual(rejected.exception.status_code, 403)

    async def test_rulebook_crud_optimistic_conflicts_and_default_deny(self):
        probe = access.ConnectionTest(
            source_id=str(self.a), destination_id=str(self.b), protocol="tcp", port=22
        )
        self.assertFalse(
            (await access.connection_test(probe, request()))["data"]["allowed"]
        )
        created = (await access.create_book(self.book(), request()))["data"]
        self.assertTrue(
            (await access.connection_test(probe, request()))["data"]["allowed"]
        )
        reverse = access.ConnectionTest(
            source_id=str(self.b), destination_id=str(self.a), protocol="tcp", port=22
        )
        self.assertFalse(
            (await access.connection_test(reverse, request()))["data"]["allowed"]
        )
        updated = self.book(revision=1)
        updated.enabled = False
        await access.update_book(created["_id"], updated, request())
        self.assertFalse(
            (await access.connection_test(probe, request()))["data"]["allowed"]
        )
        with self.assertRaises(HTTPException) as rejected:
            await access.update_book(created["_id"], updated, request())
        self.assertEqual(rejected.exception.status_code, 409)
        with self.assertRaises(HTTPException):
            await access.delete_book(
                created["_id"], access.DeleteBook(revision=1), request()
            )
        await access.delete_book(
            created["_id"], access.DeleteBook(revision=2), request()
        )

    async def test_cross_workspace_selectors_and_missing_machines_are_rejected(self):
        book = self.book()
        book.rules[0].sources = [Selector(kind="machine", id=str(ObjectId()))]
        with self.assertRaises(HTTPException):
            await access.create_book(book, request())

    async def test_group_memberships_preserve_other_tags_and_legacy_groups(self):
        await access.group_members(
            str(self.dev),
            access.GroupMembers(machine_ids=[str(self.b)], user_ids=[str(self.owner)]),
            request(),
        )
        a, b = await self.db.machines.find_one(
            {"_id": self.a}
        ), await self.db.machines.find_one({"_id": self.b})
        self.assertNotIn(self.dev, a["group_ids"])
        self.assertEqual(set(b["group_ids"]), {self.dev, self.prod})
        self.assertNotIn("group_id", b)
        self.assertEqual(
            (await self.db.machine_groups.find_one({"_id": self.dev}))["user_ids"],
            [self.owner],
        )
        with self.assertRaises(HTTPException):
            await access.group_members(
                str(self.dev),
                access.GroupMembers(user_ids=[str(self.other)]),
                request(),
            )

    async def test_invite_hash_expiry_email_binding_and_single_use(self):
        invitation = await access.invite_member(
            access.Invite(email="alice@example.test"), request()
        )
        stored = await self.db.workspace_invites.find_one({})
        self.assertNotEqual(stored["_id"], invitation["token"])
        self.assertNotIn(invitation["token"], str(stored))
        with self.assertRaises(HTTPException):
            await workspaces.accept_invitation(
                {"_id": self.other, "username": "other@example.test"},
                invitation["token"],
            )
        person = {"_id": self.alice, "username": "alice@example.test"}
        result = await asyncio.gather(
            *[
                workspaces.accept_invitation(person, invitation["token"])
                for _ in range(4)
            ],
            return_exceptions=True,
        )
        self.assertEqual(sum(isinstance(item, str) for item in result), 1)
        self.assertEqual(
            await self.db.workspace_members.count_documents(
                {"workspace_id": self.owner}
            ),
            1,
        )
        self.assertEqual(
            await workspaces.workspace_access(person, str(self.owner)),
            (self.owner, "member"),
        )

    async def test_expired_revoked_and_removed_issuer_invitations_fail_closed(self):
        await self.member("admin")
        with patch.object(
            access,
            "get_authenticated_user",
            AsyncMock(return_value={"_id": self.alice}),
        ):
            with self.assertRaises(HTTPException):
                await access.invite_member(
                    access.Invite(email="new@example.test", role="admin"),
                    request(self.owner),
                )
            invitation = await access.invite_member(
                access.Invite(email="new@example.test"), request(self.owner)
            )
        await access.remove_member(str(self.alice), request())
        with self.assertRaises(HTTPException):
            await workspaces.valid_invitation(invitation["token"])
        other = await access.invite_member(
            access.Invite(email="new@example.test"), request()
        )
        await self.db.workspace_invites.update_one(
            {"_id": workspaces.token_digest(other["token"])},
            {"$set": {"expires_at": access.utcnow() - timedelta(seconds=1)}},
        )
        with self.assertRaises(HTTPException):
            await workspaces.valid_invitation(other["token"])

    async def test_removal_purges_people_tags_but_owner_cannot_be_removed(self):
        await self.member()
        await self.db.machines.update_one(
            {"_id": self.a}, {"$set": {"private_owner_id": self.alice}}
        )
        await self.db.machine_groups.update_one(
            {"_id": self.dev}, {"$set": {"user_ids": [self.alice]}}
        )
        await access.remove_member(str(self.alice), request())
        self.assertTrue(
            (await self.db.machines.find_one({"_id": self.a}))["private_owner_revoked"]
        )
        self.assertEqual(
            (await self.db.machine_groups.find_one({"_id": self.dev}))["user_ids"], []
        )
        with self.assertRaises(HTTPException):
            await workspaces.workspace_access({"_id": self.alice}, str(self.owner))
        with self.assertRaises(HTTPException):
            await access.remove_member(str(self.owner), request())

    def test_cross_origin_and_opaque_writes_fail_closed(self):
        for origin in ["https://evil.example", "null", "https://[invalid"]:
            req = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/",
                    "query_string": b"",
                    "headers": [
                        (b"host", b"porthub.example"),
                        (b"origin", origin.encode()),
                    ],
                }
            )
            with self.assertRaises(HTTPException) as rejected:
                access.check_origin(req)
            self.assertEqual(rejected.exception.status_code, 403)
        req = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/",
                "query_string": b"",
                "headers": [
                    (b"host", b"porthub.example"),
                    (b"origin", b"https://porthub.example"),
                ],
            }
        )
        access.check_origin(req)

    async def test_explicit_invitation_allows_registration_with_public_signup_disabled(
        self,
    ):
        invitation = await access.invite_member(
            access.Invite(email="new@example.test"), request()
        )
        data = UserSignupDto(
            name="New Person",
            username="new@example.test",
            password="a-strong-test-password",
            invitation_token=invitation["token"],
        )
        with patch.object(signup, "db", self.db), patch.object(
            signup, "SIGNUP_DISABLED", True
        ), patch.object(signup, "start_session", AsyncMock()):
            response = await signup.signup(data, request(), Response())
            self.assertEqual(response["workspace_id"], str(self.owner))
            created = await self.db.users.find_one({"username": "new@example.test"})
            self.assertEqual(created["role"], "user")
            self.assertEqual(
                await workspaces.workspace_access(created, str(self.owner)),
                (self.owner, "member"),
            )
            with self.assertRaises(HTTPException):
                await signup.signup(
                    UserSignupDto(
                        name="Not Invited",
                        username="no@example.test",
                        password="a-strong-test-password",
                    ),
                    request(),
                    Response(),
                )
