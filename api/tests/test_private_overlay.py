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

    def test_all_machines_selector_reaches_every_workspace_machine(self):
        machines = [
            {"_id": "luna", "user_id": "ws", "group_ids": ["home"]},
            {"_id": "miro", "user_id": "ws", "group_ids": ["home"]},
            {"_id": "condor", "user_id": "ws", "group_ids": ["lab"]},
            {"_id": "foreign", "user_id": "other", "group_ids": ["lab"]},
        ]
        groups = {"home": {"user_ids": []}, "lab": {"user_ids": []}}
        rule = {"id": "r", "name": "Luna to everything", "sources": [{"kind": "machine", "id": "luna"}],
                "destinations": [{"kind": "all", "id": "machines"}], "protocol": "any", "ports": ""}
        grants = compile_grants(machines, [{"_id": "b", "user_id": "ws", "group_id": "home", "rules": [rule]}], groups)
        # Luna reaches every machine of its workspace, across groups, and never
        # another workspace's machine; nothing is granted in reverse.
        self.assertEqual({(g["source"], g["destination"]) for g in grants}, {("luna", "miro"), ("luna", "condor")})
        everyone = dict(rule, sources=[{"kind": "all", "id": "machines"}], bidirectional=True)
        grants = compile_grants(machines, [{"_id": "b", "user_id": "ws", "group_id": "home", "rules": [everyone]}], groups)
        self.assertEqual(len({(g["source"], g["destination"]) for g in grants}), 6)  # every ordered pair of 3
        from shared.access_policy import Selector
        with self.assertRaises(ValueError):
            Selector(kind="all", id="something-else")


class MachineNameTests(unittest.TestCase):
    def test_comma_separated_names_are_cleaned(self):
        from router.common import split_machine_names
        self.assertEqual(split_machine_names(" Luna ,lunabox,  lb ,, LUNA "), ("Luna", ["lunabox", "lb"]))
        with self.assertRaises(Exception):
            split_machine_names(" , ")
