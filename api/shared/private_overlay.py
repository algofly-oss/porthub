"""Private-only address allocation and policy compilation.

No public port, proxy, Rathole, machine enrollment, or firewall configuration is
written by this module. A private peer must be explicitly enabled by its admin.
"""

import hashlib
import ipaddress
import re

from shared.access_policy import AccessRule, entity_matches, parse_ports

FINGERPRINT = re.compile(r"(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}\Z")


def private_address(cidr, machine_id, occupied):
    network = ipaddress.ip_network(cidr, strict=True)
    hosts = network.num_addresses - 2
    start = int.from_bytes(hashlib.sha256(str(machine_id).encode()).digest()[:8], "big") % hosts
    for offset in range(hosts):
        address = str(network.network_address + 1 + ((start + offset) % hosts))
        if address not in occupied:
            return address
    raise ValueError("The private address range is full")


def compile_grants(machines, books, groups):
    """Compile named selectors to explicit machine-pair grants for client ACLs.

    Compiling selectors on the server keeps per-packet policy evaluation small
    and avoids leaking another member's email or account details to clients.
    """
    machines = [m for m in machines if m.get("enabled", True) and not m.get("private_owner_revoked")]
    grants = {}
    for book in books:
        if not book.get("enabled", True) or str(book.get("group_id")) not in groups:
            continue
        for raw in book.get("rules", []):
            try:
                rule = AccessRule(**raw).dict()
            except (ValueError, TypeError):
                continue
            if not rule["enabled"]:
                continue
            sources = [m for m in machines if str(m.get("user_id")) == str(book.get("user_id")) and any(entity_matches(s, m, groups) for s in rule["sources"])]
            destinations = [m for m in machines if str(m.get("user_id")) == str(book.get("user_id")) and any(entity_matches(s, m, groups) for s in rule["destinations"])]
            ports = parse_ports(rule["ports"])
            for source in sources:
                for destination in destinations:
                    pairs = [(source, destination)]
                    if rule["bidirectional"]:
                        pairs.append((destination, source))
                    for left, right in pairs:
                        if left["_id"] == right["_id"]:
                            continue
                        key = (str(left["_id"]), str(right["_id"]), rule["protocol"], tuple(ports))
                        grants[key] = {
                            "source": key[0], "destination": key[1], "protocol": key[2],
                            "ports": [{"start": start, "end": end} for start, end in ports],
                        }
    return list(grants.values())
