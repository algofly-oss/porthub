import asyncio
import logging

import requests

from shared.env import (
    FIREWALL_API_KEY,
    FIREWALL_BASE_URL,
    FIREWALL_REQUEST_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


class FirewallClientError(Exception):
    pass


def is_firewall_configured() -> bool:
    return bool(FIREWALL_BASE_URL and FIREWALL_API_KEY)


def get_stored_connection_firewall_policy(connection: dict) -> dict:
    firewall = connection.get("firewall")
    if isinstance(firewall, dict):
        return {
            "is_public": bool(firewall.get("is_public", True)),
            "allowed_ips": [str(ip) for ip in firewall.get("allowed_ips", [])],
        }

    return {
        "is_public": True,
        "allowed_ips": [],
    }


def _build_url(path: str) -> str:
    if not is_firewall_configured():
        raise FirewallClientError("Firewall integration is not configured")
    return f"{FIREWALL_BASE_URL}{path}"


async def _request(method: str, path: str, *, json: dict | None = None) -> dict:
    url = _build_url(path)

    try:
        response = await asyncio.to_thread(
            requests.request,
            method,
            url,
            json=json,
            headers={"x-api-key": FIREWALL_API_KEY},
            timeout=FIREWALL_REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise FirewallClientError(f"Firewall request failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError:
        payload = {"detail": response.text}

    if response.status_code >= 400:
        detail = payload.get("detail") or payload.get("msg") or "Firewall request failed"
        raise FirewallClientError(detail)

    return payload


async def get_port_policy(port: int) -> dict:
    payload = await _request("GET", f"/ports/{port}/policy")
    return payload.get("data", {})


async def update_port_policy(port: int, *, is_public: bool, allowed_ips: list[str]) -> dict:
    payload = await _request(
        "PUT",
        f"/ports/{port}/policy",
        json={
            "is_public": is_public,
            "allowed_ips": allowed_ips,
        },
    )
    return payload.get("data", {})


async def delete_port_policy(port: int) -> dict:
    payload = await _request("DELETE", f"/ports/{port}/policy")
    return payload.get("data", {})


async def list_active_ports() -> list[dict]:
    payload = await _request("GET", "/ports/active")
    return payload.get("data", [])


async def get_traffic_snapshot(ports: list[int]) -> dict:
    payload = await _request(
        "POST",
        "/ports/traffic/snapshot",
        json={"ports": ports},
    )
    return payload.get("data", {})


async def get_recent_ip_hits(port: int, limit: int = 10) -> list[dict]:
    payload = await _request(
        "GET",
        f"/ports/{port}/recent-ip-hits?limit={limit}",
    )
    return payload.get("data", [])


async def delete_port_policy_best_effort(port: int) -> None:
    if not is_firewall_configured():
        return

    try:
        await delete_port_policy(port)
    except FirewallClientError:
        logger.warning("Failed to delete firewall policy for port %s", port, exc_info=True)


async def sync_connection_firewall_policy(connection: dict) -> None:
    if not is_firewall_configured():
        return

    port = connection.get("external_port")
    if not isinstance(port, int):
        return

    policy = get_stored_connection_firewall_policy(connection)
    if connection.get("enabled", True) is False:
        await delete_port_policy_best_effort(port)
        return

    try:
        await update_port_policy(
            port,
            is_public=bool(policy["is_public"]),
            allowed_ips=policy["allowed_ips"],
        )
    except FirewallClientError:
        logger.warning("Failed to sync firewall policy for port %s", port, exc_info=True)


async def sync_machine_connection_firewall_policies(machine_id) -> None:
    from shared.factory import db

    connections = await db.connections.find({"machine_id": machine_id}).to_list(length=None)
    for connection in connections:
        await sync_connection_firewall_policy(connection)


async def delete_machine_connection_firewall_policies(machine_id) -> None:
    from shared.factory import db

    connections = await db.connections.find({"machine_id": machine_id}).to_list(length=None)
    for connection in connections:
        port = connection.get("external_port")
        if isinstance(port, int):
            await delete_port_policy_best_effort(port)


async def reconcile_firewall_state_from_db() -> None:
    from shared.factory import db

    if not is_firewall_configured():
        return

    machines = await db.machines.find({}).to_list(length=None)
    machine_by_id = {machine["_id"]: machine for machine in machines}
    connections = await db.connections.find({}).to_list(length=None)

    for connection in connections:
        machine = machine_by_id.get(connection.get("machine_id"))
        if machine is None or machine.get("enabled", True) is False:
            port = connection.get("external_port")
            if isinstance(port, int):
                await delete_port_policy_best_effort(port)
            continue

        await sync_connection_firewall_policy(connection)
