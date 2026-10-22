import os
import time
import unittest
from unittest.mock import patch

from router.access import private

SECRET = "relay-test-secret-0123456789abcdefghij"


class RelayCredentialTest(unittest.TestCase):
    def test_turn_rest_credential_matches_independent_vector(self):
        with patch.dict(os.environ, {"PORTHUB_RELAY_SECRET": SECRET}), patch.object(private.time, "time", return_value=2000000000 - private.RELAY_CREDENTIAL_SECONDS):
            server = private.relay_server("ws1:peer1")
        self.assertEqual(server["urls"], [private.RELAY_URL])
        self.assertEqual(server["username"], "2000000000:ws1:peer1")
        self.assertEqual(server["credential"], "IzYJh4k08rMvPXhBOdA0GeRS4Yo=")  # openssl dgst -sha1 -hmac | base64

    def test_relay_only_when_configured_and_expiry_in_future(self):
        with patch.dict(os.environ, {"PORTHUB_RELAY_SECRET": ""}):
            self.assertIsNone(private.relay_server("p"))
            self.assertEqual([s for s in private.ice_servers("p") if "turn:" in s["urls"][0]], [])
        with patch.dict(os.environ, {"PORTHUB_RELAY_SECRET": SECRET, "PORTHUB_PRIVATE_ICE_SERVERS": '[{"urls":["stun:stun.example.org:3478"]}]'}):
            servers = private.ice_servers("p")
        self.assertEqual(servers[0]["urls"], ["stun:stun.example.org:3478"])
        self.assertGreater(int(servers[1]["username"].split(":")[0]), time.time() + 3600)


class RelayRouteTest(unittest.TestCase):
    def test_routes_from_environment(self):
        with patch.dict(os.environ, {"PORTHUB_RELAY_ROUTES": " http://gw.example:8345/, ftp://bad , https://x.example "}):
            self.assertEqual(private.relay_routes(), ["http://gw.example:8345", "https://x.example"])
        with patch.dict(os.environ, {"PORTHUB_RELAY_ROUTES": ""}):
            self.assertEqual(private.relay_routes(), [])
