import copy
import unittest
from pydantic import ValidationError

from shared.access_policy import (
    AccessRule,
    NetworkPreferences,
    RuleBook,
    evaluate_access,
    parse_ports,
)


class AccessPolicyTest(unittest.TestCase):
    def setUp(self):
        self.a = {
            "_id": "a",
            "user_id": "workspace",
            "private_owner_id": "alice",
            "group_ids": ["dev"],
        }
        self.b = {
            "_id": "b",
            "user_id": "workspace",
            "private_owner_id": "bob",
            "group_ids": ["prod"],
        }
        self.groups = {
            "dev": {"user_id": "workspace"},
            "prod": {"user_id": "workspace"},
            "people": {"user_id": "workspace", "user_ids": ["alice"]},
        }
        self.rule = {
            "id": "ssh",
            "name": "Development SSH",
            "sources": [{"kind": "group", "id": "dev"}],
            "destinations": [{"kind": "group", "id": "prod"}],
            "protocol": "tcp",
            "ports": "22",
            "enabled": True,
        }
        self.book = {
            "_id": "book",
            "user_id": "workspace",
            "group_id": "dev",
            "rules": [self.rule],
        }

    def check(self, source=None, destination=None, protocol="tcp", port=22, books=None):
        return evaluate_access(
            source or self.a,
            destination or self.b,
            protocol,
            port,
            books if books is not None else [self.book],
            self.groups,
        )

    def test_default_deny_even_for_shared_group_and_owner(self):
        same = {**self.b, "private_owner_id": "alice", "group_ids": ["dev"]}
        self.assertFalse(self.check(destination=same, books=[])["allowed"])
        self.assertFalse(self.check(books=[{**self.book, "rules": []}])["allowed"])

    def test_explicit_one_way_allow_does_not_allow_reverse_initiation(self):
        result = self.check()
        self.assertTrue(result["allowed"])
        self.assertEqual(result["rule_id"], "ssh")
        self.assertFalse(self.check(source=self.b, destination=self.a)["allowed"])

    def test_reverse_initiation_requires_bidirectional_or_separate_rule(self):
        self.rule["bidirectional"] = True
        self.assertTrue(self.check(source=self.b, destination=self.a)["allowed"])

    def test_protocol_and_ports_and_ranges(self):
        self.rule["ports"] = "22, 8000-8090"
        for port in [22, 8000, 8050, 8090]:
            self.assertTrue(self.check(port=port)["allowed"])
        for port in [23, 7999, 8091, 0, 65536]:
            self.assertFalse(self.check(port=port)["allowed"])
        self.assertFalse(self.check(protocol="udp")["allowed"])
        self.assertFalse(self.check(protocol="icmp")["allowed"])

    def test_any_protocol_is_explicit_and_can_be_one_way(self):
        self.rule.update(protocol="any", ports="")
        for protocol in ["tcp", "udp", "icmp"]:
            self.assertTrue(self.check(protocol=protocol, port=3333)["allowed"])
            self.assertFalse(
                self.check(
                    source=self.b, destination=self.a, protocol=protocol, port=3333
                )["allowed"]
            )

    def test_user_selector_means_owned_enrolled_devices(self):
        self.rule["sources"] = [{"kind": "user", "id": "alice"}]
        self.assertTrue(self.check()["allowed"])
        self.assertFalse(
            self.check(source={**self.a, "private_owner_id": "someone-else"})["allowed"]
        )

    def test_user_group_expands_to_users_devices(self):
        self.rule["sources"] = [{"kind": "group", "id": "people"}]
        self.assertTrue(self.check()["allowed"])
        self.assertFalse(
            self.check(source={**self.a, "private_owner_id": "bob"})["allowed"]
        )

    def test_disabled_and_deleted_resources_fail_closed(self):
        self.assertFalse(self.check(source={**self.a, "enabled": False})["allowed"])
        self.assertFalse(
            self.check(destination={**self.b, "enabled": False})["allowed"]
        )
        self.assertFalse(self.check(books=[{**self.book, "enabled": False}])["allowed"])
        self.rule["enabled"] = False
        self.assertFalse(self.check()["allowed"])
        self.rule["enabled"] = True
        self.groups.pop("dev")
        self.assertFalse(self.check()["allowed"])

    def test_workspace_boundary_cannot_be_overridden_by_any_rule(self):
        self.rule.update(protocol="any", ports="", bidirectional=True)
        self.assertFalse(
            self.check(destination={**self.b, "user_id": "another"})["allowed"]
        )
        self.assertFalse(
            self.check(books=[{**self.book, "user_id": "another"}])["allowed"]
        )

    def test_allow_union_not_first_match_or_group_inheritance(self):
        self.assertTrue(
            self.check(
                books=[{**self.book, "_id": "disabled", "enabled": False}, self.book]
            )["allowed"]
        )
        self.rule["destinations"] = [{"kind": "machine", "id": "missing"}]
        self.assertFalse(self.check()["allowed"])

    def test_malformed_stored_rule_cannot_grant_access(self):
        self.rule["ports"] = "bad"
        self.assertFalse(self.check()["allowed"])

    def test_does_not_mutate_persisted_state(self):
        original = copy.deepcopy(self.book)
        self.check()
        self.assertEqual(self.book, original)

    def test_model_validation_and_canonical_ports(self):
        self.assertEqual(
            parse_ports("443, 22, 443, 8000-8090"), [(22, 22), (443, 443), (8000, 8090)]
        )
        self.assertEqual(
            AccessRule(**{**self.rule, "ports": "443,22"}).ports, "22, 443"
        )
        for ports in ["0", "65536", "90-80", "22,", "-1", "foo"]:
            with self.assertRaises(ValueError):
                parse_ports(ports)
        for protocol in ["icmp", "any"]:
            with self.assertRaises(ValidationError):
                AccessRule(**{**self.rule, "protocol": protocol})
        with self.assertRaises(ValidationError):
            RuleBook(name="Rules", group_id="dev", rules=[self.rule, self.rule])

    def test_network_preferences_reject_public_reserved_and_invalid_ranges(self):
        for cidr in [
            "1.1.1.0/24",
            "127.0.0.0/24",
            "169.254.0.0/24",
            "100.64.0.0/24",
            "10.0.0.1/24",
            "10.0.0.0/8",
            "::1/128",
        ]:
            with self.assertRaises(ValidationError):
                NetworkPreferences(cidr=cidr)
        self.assertEqual(NetworkPreferences(dns_suffix=" PH.IO. ").dns_suffix, "ph.io")
        self.assertEqual(NetworkPreferences().dns_suffix, "phub")
        self.assertEqual(NetworkPreferences(dns_suffix="Internal").dns_suffix, "internal")
        for top_level in ("com", "io", "dev"):
            with self.assertRaises(ValueError):
                NetworkPreferences(dns_suffix=top_level)
        for suffix in [
            "localhost",
            "ph.local",
            "ph..io",
            "http://ph.io",
            "ph.io/path",
            "-ph.io",
        ]:
            with self.assertRaises(ValidationError):
                NetworkPreferences(dns_suffix=suffix)
