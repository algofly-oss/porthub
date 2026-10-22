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


HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")


def hostname_label(name):
    """Default private hostname: the registered machine name as a DNS label."""
    label = re.sub(r"[^a-z0-9]+", "-", str(name or "").lower()).strip("-")[:48].strip("-")
    return label or "machine"


def assign_hostnames(machines, peers):
    """Return {peer_id: hostname label} for every peer in one workspace.

    Custom names win (they were checked for conflicts when set). Others follow
    the current machine name, so renames are picked up; a clash with any name
    already taken gets a short machine-id suffix, earliest enrollment first.
    """
    names, taken = {}, set()
    for peer in peers:
        if peer.get("hostname"):
            names[peer["_id"]] = peer["hostname"]
            taken.add(peer["hostname"])
    machine_names = {m["_id"]: m.get("name") for m in machines}
    for peer in sorted(peers, key=lambda p: (str(p.get("created_at") or ""), p["_id"])):
        if peer["_id"] in names:
            continue
        label = hostname_label(machine_names.get(peer["machine_id"]))
        if label in taken:
            label = f"{label[:43].rstrip('-')}-{str(peer['machine_id'])[-4:]}"
        names[peer["_id"]] = label
        taken.add(label)
    return names


def hostname_conflict(label, machine_id, machines, peers):
    """Name of the other machine that already owns label, or None.

    A custom name may not equal another machine's registered name (enrolled
    or not) nor any other peer's current private name.
    """
    for machine in machines:
        if machine["_id"] != machine_id and hostname_label(machine.get("name")) == label:
            return machine.get("name")
    current = assign_hostnames(machines, peers)
    names = {m["_id"]: m.get("name") for m in machines}
    for peer in peers:
        if peer["machine_id"] != machine_id and current.get(peer["_id"]) == label:
            return names.get(peer["machine_id"], "another machine")
    return None
