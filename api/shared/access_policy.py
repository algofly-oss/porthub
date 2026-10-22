"""Private-network policy model. No policies means no access.

Groups are labels, not security boundaries or implicit grants. A rule book is
owned by an existing group for organisation, but its selectors are explicit.
Users represent their enrolled devices, never an arbitrary OS login session.
Public Rathole/HTTP forwarding is intentionally outside this policy engine.
"""

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, validator, root_validator


class Selector(BaseModel):
    kind: Literal["machine", "user", "group"]
    id: str = Field(..., min_length=1, max_length=64)


def parse_ports(value):
    value = str(value or "").strip()
    if not value or value.lower() in {"any", "all", "*"}:
        return []
    ranges = []
    for item in value.split(","):
        match = re.fullmatch(r"\s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s*", item)
        if not match:
            raise ValueError("Use ports such as 22, 443, 8000-8090")
        start, end = int(match[1]), int(match[2] or match[1])
        if not 1 <= start <= end <= 65535:
            raise ValueError(
                "Ports must be between 1 and 65535, with ranges in ascending order"
            )
        ranges.append((start, end))
    if len(ranges) > 64:
        raise ValueError("Use no more than 64 port entries")
    return sorted(set(ranges))


class AccessRule(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=80)
    sources: list[Selector] = Field(..., min_items=1, max_items=32)
    destinations: list[Selector] = Field(..., min_items=1, max_items=32)
    protocol: Literal["any", "tcp", "udp", "icmp"] = "tcp"
    ports: str = Field("", max_length=512)
    bidirectional: bool = False
    enabled: bool = True

    @validator("name")
    def clean_name(cls, value):
        if not value.strip():
            raise ValueError("A rule name is required")
        return value.strip()

    @root_validator
    def valid_ports(cls, values):
        ports = parse_ports(values.get("ports", ""))
        if ports and values.get("protocol") not in {"tcp", "udp"}:
            raise ValueError("Port restrictions require TCP or UDP")
        values["ports"] = ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ports)
        return values


class RuleBook(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    group_id: str = Field(..., min_length=1, max_length=64)
    enabled: bool = True
    rules: list[AccessRule] = Field(default_factory=list, max_items=100)
    revision: int = Field(0, ge=0)

    @validator("name")
    def clean_name(cls, value):
        if not value.strip():
            raise ValueError("A rule-book name is required")
        return value.strip()

    @validator("rules")
    def unique_rule_ids(cls, rules):
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Rule identifiers must be unique inside a rule book")
        return rules


class NetworkPreferences(BaseModel):
    cidr: str = "10.203.0.0/24"
    dns_suffix: str = Field("ph.io", min_length=3, max_length=120)

    @validator("cidr")
    def private_ipv4(cls, value):
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            raise ValueError("Enter a network CIDR such as 10.203.0.0/24")
        private_ranges = [
            ipaddress.ip_network(part)
            for part in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        ]
        if (
            network.version != 4
            or not 16 <= network.prefixlen <= 28
            or not any(network.subnet_of(parent) for parent in private_ranges)
        ):
            raise ValueError("Choose an RFC1918 IPv4 range between /16 and /28")
        return str(network)

    @validator("dns_suffix")
    def valid_suffix(cls, value):
        value = value.strip().lower().rstrip(".")
        if "." not in value or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in value.split(".")
        ):
            raise ValueError("Enter a domain suffix such as ph.io")
        if value in {"localhost", "local"} or value.endswith((".localhost", ".local")):
            raise ValueError("This suffix is reserved for local OS networking")
        return value


def entity_matches(selector, machine, groups):
    kind, entity_id = selector["kind"], str(selector["id"])
    if kind == "machine":
        return str(machine["_id"]) == entity_id
    owner = str(machine.get("private_owner_id") or machine.get("user_id") or "")
    if kind == "user":
        return owner == entity_id
    group = groups.get(entity_id)
    if kind != "group" or group is None:
        return False
    ids = machine.get("group_ids") or (
        [machine["group_id"]] if machine.get("group_id") else []
    )
    return entity_id in {str(item) for item in ids} or owner in {
        str(item) for item in group.get("user_ids", [])
    }


def evaluate_access(source, destination, protocol, port, books, groups):
    """Evaluate initiation only. Established replies are handled by conntrack.

    Allow-only policies combine by union, never list order. Missing/disabled
    identities, malformed rules and deleted groups all fail closed.
    """
    denied = {
        "allowed": False,
        "rule_id": None,
        "book_id": None,
        "reason": "No enabled rule allows this connection",
    }
    if (
        not source
        or not destination
        or source.get("enabled", True) is False
        or destination.get("enabled", True) is False
        or source.get("private_owner_revoked", False)
        or destination.get("private_owner_revoked", False)
    ):
        return {**denied, "reason": "Both machines must be enabled"}
    if str(source.get("user_id")) != str(destination.get("user_id")):
        return {**denied, "reason": "Machines belong to different workspaces"}
    if protocol not in {"tcp", "udp", "icmp"} or (
        protocol in {"tcp", "udp"} and not isinstance(port, int)
    ):
        return {**denied, "reason": "Unsupported protocol or invalid port"}
    if protocol in {"tcp", "udp"} and not 1 <= port <= 65535:
        return {**denied, "reason": "Port is outside the supported range"}
    for book in books:
        if not book.get("enabled", True) or str(book.get("group_id")) not in groups:
            continue
        if str(book.get("user_id")) != str(source.get("user_id")):
            continue
        for raw_rule in book.get("rules", []):
            try:
                rule = AccessRule(**raw_rule).dict()
            except (ValueError, TypeError):
                continue
            if not rule["enabled"] or rule["protocol"] not in {"any", protocol}:
                continue
            ranges = parse_ports(rule["ports"])
            if ranges and not any(start <= port <= end for start, end in ranges):
                continue

            def matches(left, right):
                return any(
                    entity_matches(s, left, groups) for s in rule["sources"]
                ) and any(
                    entity_matches(d, right, groups) for d in rule["destinations"]
                )

            if matches(source, destination) or (
                rule["bidirectional"] and matches(destination, source)
            ):
                return {
                    "allowed": True,
                    "rule_id": rule["id"],
                    "book_id": str(book["_id"]),
                    "reason": rule["name"],
                }
    return denied
