import ipaddress
import unittest

from shared.access_policy import evaluate_access
from shared.private_overlay import compile_grants, private_address, FINGERPRINT


class PrivateOverlayTests(unittest.TestCase):
    def test_address_allocation_is_stable_unique_and_bounded(self):
        occupied = set()
        for index in range(14):
            address = private_address("10.203.0.0/28", str(index), occupied)
            self.assertIn(ipaddress.ip_address(address), ipaddress.ip_network("10.203.0.0/28"))
            self.assertNotIn(address, {"10.203.0.0", "10.203.0.15"})
            self.assertEqual(address, private_address("10.203.0.0/28", str(index), occupied))
            occupied.add(address)
        with self.assertRaises(ValueError):
            private_address("10.203.0.0/28", "overflow", occupied)

    def test_compiler_matches_policy_evaluator(self):
        machines = [
            {"_id": "a", "user_id": "workspace", "private_owner_id": "alice", "group_ids": ["dev"]},
            {"_id": "b", "user_id": "workspace", "private_owner_id": "bob", "group_ids": ["prod"]},
            {"_id": "c", "user_id": "other", "group_ids": ["prod"]},
            {"_id": "d", "user_id": "workspace", "enabled": False, "group_ids": ["prod"]},
        ]
        groups = {"dev": {"user_ids": []}, "prod": {"user_ids": []}}
        rules = [
            {"id": "ssh", "name": "SSH", "sources": [{"kind": "user", "id": "alice"}], "destinations": [{"kind": "group", "id": "prod"}], "protocol": "tcp", "ports": "22, 8000-8002"},
            {"id": "dns", "name": "DNS", "sources": [{"kind": "group", "id": "dev"}], "destinations": [{"kind": "group", "id": "prod"}], "protocol": "udp", "ports": "53", "bidirectional": True},
        ]
        books = [{"_id": "book", "user_id": "workspace", "group_id": "dev", "rules": rules}]
        grants = compile_grants(machines, books, groups)
        for source in machines:
            for destination in machines:
                if source == destination:
                    continue
                for protocol in ["tcp", "udp", "icmp"]:
                    for port in [22, 23, 53, 8000, 8002, 8003]:
                        expected = evaluate_access(source, destination, protocol, port, books, groups)["allowed"]
                        actual = any(g["source"] == source["_id"] and g["destination"] == destination["_id"] and g["protocol"] in {protocol, "any"} and (not g["ports"] or any(p["start"] <= port <= p["end"] for p in g["ports"])) for g in grants)
                        self.assertEqual(expected, actual, (source["_id"], destination["_id"], protocol, port))
        self.assertEqual(compile_grants(machines, [], groups), [])
        books[0]["enabled"] = False
        self.assertEqual(compile_grants(machines, books, groups), [])

    def test_fingerprint_format(self):
        self.assertTrue(FINGERPRINT.fullmatch(":".join(["AB"] * 32)))
        self.assertIsNone(FINGERPRINT.fullmatch("AB:" * 32))
        self.assertIsNone(FINGERPRINT.fullmatch("sha1:insecure"))
