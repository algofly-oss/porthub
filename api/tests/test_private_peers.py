"""Private enrollment/signaling integration against an isolated Mongo database."""
import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

from bson import ObjectId
from fastapi import HTTPException, Response

from router.access import private
from tests.test_access_workspaces import AccessWorkspaceTest, request


class PrivatePeerTests(AccessWorkspaceTest):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        p = patch.object(private, "db", self.db)
        p.start()
        self.patches.append(p)

    async def enroll(self, machine, alias):
        result = await private.enroll_peer(private.PeerEnrollment(machine_id=str(machine), alias=alias), request())
        credential = await private.bootstrap(private.Bootstrap(ticket=result["ticket"]), Response())
        return result, credential

    def payload(self, credential, letter):
        return private.ClientSync(peer_id=credential["peer_id"], token=credential["token"], fingerprint=":".join([letter * 2] * 32), instance=letter * 32)

    async def allow(self):
        await self.db.access_rulebooks.insert_one({
            "user_id": self.owner, "group_id": str(self.dev), "enabled": True,
            "rules": [{"id": "ssh", "name": "SSH", "enabled": True, "sources": [{"kind": "machine", "id": str(self.a)}], "destinations": [{"kind": "machine", "id": str(self.b)}], "protocol": "tcp", "ports": "22"}],
        })

    async def test_private_credentials_and_tickets_are_separate_single_use(self):
        before = await self.db.machines.find_one({"_id": self.a})
        enrollment = await private.enroll_peer(private.PeerEnrollment(machine_id=str(self.a), alias="laptop"), request())
        self.assertNotIn("TOP-SECRET", str(enrollment))
        async def claim():
            try:
                return await private.bootstrap(private.Bootstrap(ticket=enrollment["ticket"]), Response())
            except HTTPException:
                return None
        claims = await asyncio.gather(*[claim() for _ in range(4)])
        self.assertEqual(sum(c is not None for c in claims), 1)
        credential = next(c for c in claims if c)
        stored = await self.db.private_peers.find_one({"_id": enrollment["peer_id"]})
        self.assertNotEqual(stored["credential_hash"], credential["token"])
        self.assertNotIn("token", stored)
        self.assertEqual(before, await self.db.machines.find_one({"_id": self.a}))
        self.assertEqual(await self.db.connections.count_documents({}), 0)
        self.assertEqual(await self.db.traffic_routes.count_documents({}), 0)

    async def test_default_deny_and_compiled_lease_with_revocation(self):
        _, a = await self.enroll(self.a, "laptop")
        _, b = await self.enroll(self.b, "server")
        pa, pb = self.payload(a, "A"), self.payload(b, "B")
        first = await private.sync(pa, Response())
        self.assertEqual(first["snapshot"]["grants"], [])
        self.assertEqual(len(first["snapshot"]["peers"]), 1)
        await private.sync(pb, Response())
        await self.allow()
        allowed = await private.sync(pa, Response())
        snapshot = allowed["snapshot"]
        self.assertGreater(snapshot["revision"], first["snapshot"]["revision"])
        self.assertEqual(len(snapshot["peers"]), 2)
        self.assertEqual(snapshot["grants"], [{"source": a["peer_id"], "destination": b["peer_id"], "protocol": "tcp", "ports": [{"start": 22, "end": 22}]}])
        self.assertLessEqual((snapshot["expires_at"] - datetime.now(timezone.utc)).total_seconds(), 15)
        await self.db.access_rulebooks.update_many({}, {"$set": {"enabled": False}})
        revoked = await private.sync(pa, Response())
        self.assertEqual(revoked["snapshot"]["grants"], [])
        self.assertEqual(len(revoked["snapshot"]["peers"]), 1)

    async def test_signaling_is_scoped_pinned_and_deduplicated(self):
        _, a = await self.enroll(self.a, "laptop")
        _, b = await self.enroll(self.b, "server")
        pa, pb = self.payload(a, "A"), self.payload(b, "B")
        await private.sync(pa, Response())
        await private.sync(pb, Response())
        await self.allow()
        pa.signals = [private.Signal(to=b["peer_id"], session="a" * 32, description=private.Description(type="offer", sdp=f"v=0\r\na=fingerprint:sha-256 {pa.fingerprint}\r\n"))]
        await private.sync(pa, Response())
        await private.sync(pa, Response())
        received = await private.sync(pb, Response())
        self.assertEqual(len(received["signals"]), 1)
        message = received["signals"][0]
        self.assertEqual(message["from"], a["peer_id"])
        pb.acks = [message["id"]]
        self.assertEqual((await private.sync(pb, Response()))["signals"], [])
        pa.signals[0].description.sdp = "v=0\r\na=fingerprint:sha-256 " + pb.fingerprint
        with self.assertRaises(HTTPException) as error:
            await private.sync(pa, Response())
        self.assertEqual(error.exception.status_code, 400)

    async def test_disable_and_revoke_do_not_change_public_machine(self):
        before = await self.db.machines.find_one({"_id": self.a})
        _, credential = await self.enroll(self.a, "laptop")
        await private.change_peer(credential["peer_id"], private.PeerChange(enabled=False), request())
        with self.assertRaises(HTTPException):
            await private.sync(self.payload(credential, "A"), Response())
        await private.change_peer(credential["peer_id"], private.PeerChange(enabled=True), request())
        await private.sync(self.payload(credential, "A"), Response())
        await private.revoke_peer(credential["peer_id"], request())
        with self.assertRaises(HTTPException):
            await private.sync(self.payload(credential, "A"), Response())
        self.assertEqual(before, await self.db.machines.find_one({"_id": self.a}))

    async def test_alias_collision_and_cross_workspace_are_denied(self):
        await self.enroll(self.a, "same-name")
        with self.assertRaises(HTTPException) as error:
            await private.enroll_peer(private.PeerEnrollment(machine_id=str(self.b), alias="same-name"), request())
        self.assertEqual(error.exception.status_code, 409)
        foreign = ObjectId()
        await self.db.machines.insert_one({"_id": foreign, "user_id": self.other})
        with self.assertRaises(HTTPException) as error:
            await private.enroll_peer(private.PeerEnrollment(machine_id=str(foreign), alias="foreign"), request())
        self.assertEqual(error.exception.status_code, 403)

    async def names(self, credential, letter):
        snapshot = (await private.sync(self.payload(credential, letter), Response()))["snapshot"]
        return {p["id"]: p["hostname"] for p in snapshot["peers"]}

    async def test_private_names_follow_machine_names(self):
        _, a = await self.enroll(self.a, None)
        self.assertEqual((await self.names(a, "A"))[a["peer_id"]], "laptop.phub")
        await self.db.machines.update_one({"_id": self.a}, {"$set": {"name": "Luna Box!"}})
        self.assertEqual((await self.names(a, "A"))[a["peer_id"]], "luna-box.phub")
        # Each workspace's own suffix applies to its machines.
        await self.db.private_networks.insert_one({"_id": str(self.owner), "cidr": "10.203.0.0/24", "dns_suffix": "internal"})
        self.assertEqual((await self.names(a, "A"))[a["peer_id"]], "luna-box.internal")

    async def test_custom_names_cannot_take_another_machines_name(self):
        _, a = await self.enroll(self.a, None)
        # "server" is the registered name of machine b, even though b is not enrolled.
        with self.assertRaises(HTTPException) as error:
            await private.rename_peer(a["peer_id"], private.HostnameChange(hostname="Server"), request())
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual((await private.rename_peer(a["peer_id"], private.HostnameChange(hostname="workstation"), request()))["hostname"], "workstation")
        self.assertEqual((await self.names(a, "A"))[a["peer_id"]], "workstation.phub")
        for custom in ("workstation", "laptop"):  # b cannot take a's custom or registered name
            with self.assertRaises(HTTPException) as error:
                await private.enroll_peer(private.PeerEnrollment(machine_id=str(self.b), hostname=custom), request())
            self.assertEqual(error.exception.status_code, 409)
        with self.assertRaises(ValueError):
            private.HostnameChange(hostname="-bad-")
        self.assertEqual((await private.rename_peer(a["peer_id"], private.HostnameChange(hostname=""), request()))["hostname"], "laptop")

    async def test_duplicate_machine_names_get_distinct_private_names(self):
        await self.db.machines.update_one({"_id": self.b}, {"$set": {"name": "Laptop"}})
        _, a = await self.enroll(self.a, None)
        _, b = await self.enroll(self.b, None)
        await self.allow()
        await self.names(b, "B")
        names = await self.names(a, "A")
        self.assertEqual(names[a["peer_id"]], "laptop.phub")
        self.assertEqual(names[b["peer_id"]], f"laptop-{str(self.b)[-4:]}.phub")

    async def test_removed_inviter_cannot_bootstrap(self):
        from router import access
        await self.db.workspace_members.insert_one({"_id": f"{self.owner}:{self.alice}", "workspace_id": self.owner, "user_id": self.alice, "role": "admin"})
        with patch.object(access, "get_authenticated_user", return_value={"_id": self.alice}):
            enrollment = await private.enroll_peer(private.PeerEnrollment(machine_id=str(self.a), alias="laptop"), request(self.owner))
        await self.db.workspace_members.delete_many({})
        with self.assertRaises(HTTPException):
            await private.bootstrap(private.Bootstrap(ticket=enrollment["ticket"]), Response())
