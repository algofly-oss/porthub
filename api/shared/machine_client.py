import asyncio
import hashlib
import json
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlencode, urlsplit

from bson import ObjectId
from fastapi import HTTPException, Request

from shared.client_release import get_client_version as get_latest_client_version
from shared.env import (
    MACHINE_CONFIG_LONG_POLL_INTERVAL_SECONDS,
    MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS,
    PORT_HUB_PUBLIC_BASE_URL,
    PORT_HUB_SERVICE_DOMAIN,
    RATHOLE_PORT,
    RATHOLE_SERVER_ADDRESS,
)
from shared.factory import db
from router.common import resolve_machine_hostname


def parse_machine_object_id(value: str, detail: str = "Invalid machine id") -> ObjectId:
    if not value or not ObjectId.is_valid(value):
        raise HTTPException(status_code=400, detail=detail)
    return ObjectId(value)


async def authenticate_machine(machine_id: str, token: str) -> dict:
    machine = await db.machines.find_one(
        {
            "_id": parse_machine_object_id(machine_id),
            "token": token,
        }
    )
    if not machine:
        raise HTTPException(
            status_code=410,
            detail="Machine deleted",
            headers={"X-PortHub-Machine-Deleted": "true"},
        )
    if machine.get("deletion_pending", False):
        raise HTTPException(
            status_code=410,
            detail="Machine deleted",
            headers={"X-PortHub-Machine-Deleted": "true"},
        )
    if machine.get("enabled", True) is False:
        raise HTTPException(
            status_code=403,
            detail="Machine disabled",
            headers={"X-PortHub-Machine-Disabled": "true"},
        )
    return machine


async def authenticate_machine_for_logs(machine_id: str, token: str) -> dict:
    machine_object_id = parse_machine_object_id(machine_id)
    machine = await db.machines.find_one({"_id": machine_object_id})
    if not machine:
        raise HTTPException(
            status_code=410,
            detail="Machine deleted",
            headers={"X-PortHub-Machine-Deleted": "true"},
        )
    if machine.get("deletion_pending", False):
        raise HTTPException(
            status_code=410,
            detail="Machine deleted",
            headers={"X-PortHub-Machine-Deleted": "true"},
        )
    return machine


def get_request_client_ip(request: Request | None = None) -> str:
    if request is None:
        return ""

    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        first_hop = forwarded_for.split(",")[0].strip()
        if first_hop:
            return first_hop

    if request.client and request.client.host:
        return request.client.host

    return ""


def _normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


CLIENT_SETUP_QUERY_TO_FIELD = {
    "public_base_url": "client_setup_public_base_url",
    "rathole_server_address": "client_setup_rathole_server_address",
    "service_domain": "client_setup_service_domain",
}


def get_client_setup_request_overrides(request: Request | None = None) -> dict[str, str]:
    if request is None:
        return {}

    overrides: dict[str, str] = {}
    for query_key, field in CLIENT_SETUP_QUERY_TO_FIELD.items():
        value = (request.query_params.get(query_key) or "").strip()
        if value:
            overrides[field] = value
    return overrides


def _machine_override(
    machine: dict | None,
    field: str,
    overrides: dict[str, str] | None = None,
) -> str:
    if overrides:
        value = (overrides.get(field) or "").strip()
        if value:
            return value
    if not machine:
        return ""
    return (machine.get(field) or "").strip()


def get_public_base_url(request: Request | None = None) -> str:
    configured_base_url = (PORT_HUB_PUBLIC_BASE_URL or "").strip()
    if configured_base_url:
        return _normalize_base_url(configured_base_url)

    if request is None:
        return "http://localhost"

    return _normalize_base_url(str(request.base_url))


def get_machine_public_base_url(
    machine: dict | None = None,
    request: Request | None = None,
    overrides: dict[str, str] | None = None,
) -> str:
    configured_base_url = _machine_override(
        machine, "client_setup_public_base_url", overrides
    )
    if configured_base_url:
        return _normalize_base_url(configured_base_url)
    return get_public_base_url(request)


def get_api_base_url(
    request: Request | None = None,
    machine: dict | None = None,
    overrides: dict[str, str] | None = None,
) -> str:
    return f"{get_machine_public_base_url(machine, request, overrides)}/api"


def get_client_setup_service_domain(
    machine: dict | None = None,
    overrides: dict[str, str] | None = None,
) -> str:
    return (
        _machine_override(machine, "client_setup_service_domain", overrides)
        or PORT_HUB_SERVICE_DOMAIN
    )


def get_rathole_server_address(
    request: Request | None = None,
    machine: dict | None = None,
    overrides: dict[str, str] | None = None,
) -> str:
    configured_address = _machine_override(
        machine, "client_setup_rathole_server_address", overrides
    ) or (RATHOLE_SERVER_ADDRESS or "").strip()
    if configured_address:
        return configured_address

    public_base_url = get_machine_public_base_url(machine, request, overrides)
    parsed = urlsplit(public_base_url)
    hostname = parsed.hostname
    if not hostname:
        hostname = "localhost"

    return f"{hostname}:{RATHOLE_PORT}"


def build_machine_service_key(connection: dict) -> str:
    connection_id = str(connection.get("_id", "service"))
    return f"porthub_{connection.get('external_port', 'port')}_{connection_id}"


def format_local_address(host: str, port: int) -> str:
    normalized_host = (host or "0.0.0.0").strip() or "0.0.0.0"
    if ":" in normalized_host and not normalized_host.startswith("["):
        return f"[{normalized_host}]:{port}"
    return f"{normalized_host}:{port}"


async def load_machine_connections(machine: dict) -> list[dict]:
    return (
        await db.connections.find(
            {
                "machine_id": machine["_id"],
            }
        )
        .sort([("external_port", 1), ("_id", 1)])
        .to_list(length=None)
    )


def serialize_machine_connection(connection: dict, machine: dict) -> dict[str, Any]:
    internal_port = connection["internal_port"]
    internal_ip = connection.get("internal_ip", connection.get("internalIp", "0.0.0.0"))
    return {
        "_id": str(connection["_id"]),
        "machine_id": str(machine["_id"]),
        "service_key": build_machine_service_key(connection),
        "service_name": connection.get("service_name", ""),
        "service_description": connection.get("service_description", ""),
        "internal_ip": internal_ip,
        "internal_port": internal_port,
        "external_port": connection["external_port"],
        "enabled": connection.get("enabled", True),
        "local_address": format_local_address(internal_ip, internal_port),
    }


def build_machine_config_version(machine: dict, connections: list[dict]) -> str:
    payload = {
        "machine_id": str(machine["_id"]),
        "token": machine.get("token", ""),
        "enabled": bool(machine.get("enabled", True)),
        "client_setup_rathole_server_address": _machine_override(
            machine, "client_setup_rathole_server_address"
        ),
        "connections": [
            {
                "_id": str(connection["_id"]),
                "service_name": connection.get("service_name", ""),
                "service_description": connection.get("service_description", ""),
                "internal_ip": connection.get("internal_ip", connection.get("internalIp", "0.0.0.0")),
                "internal_port": connection.get("internal_port"),
                "external_port": connection.get("external_port"),
                "enabled": connection.get("enabled", True),
                "updated_at": connection.get("updated_at").isoformat()
                if isinstance(connection.get("updated_at"), datetime)
                else None,
            }
            for connection in connections
        ],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return digest


def render_client_toml(
    machine: dict,
    connections: list[dict],
    *,
    request: Request | None = None,
    overrides: dict[str, str] | None = None,
) -> str:
    lines = [
        "# Managed by PortHub. Manual changes will be overwritten.",
        "[client]",
        f'remote_addr = "{get_rathole_server_address(request, machine, overrides)}"',
        "",
    ]

    for connection in connections:
        if connection.get("enabled", True) is False:
            continue

        service = serialize_machine_connection(connection, machine)
        lines.extend(
            [
                f"[client.services.{service['service_key']}]",
                f'token = "{machine["token"]}"',
                f'local_addr = "{service["local_address"]}"',
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def _with_client_setup_query(url: str, overrides: dict[str, str]) -> str:
    if not overrides:
        return url

    query_values = {
        query_key: overrides[field]
        for query_key, field in CLIENT_SETUP_QUERY_TO_FIELD.items()
        if (overrides.get(field) or "").strip()
    }
    if not query_values:
        return url

    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(query_values)}"


def build_machine_endpoints(machine: dict, *, request: Request | None = None) -> dict[str, str]:
    overrides = get_client_setup_request_overrides(request)
    api_base_url = get_api_base_url(request, machine, overrides)
    machine_id = str(machine["_id"])
    token = machine["token"]
    machine_api_base_url = f"{api_base_url}/machines/{machine_id}/{token}"

    endpoints = {
        "auth": f"{api_base_url}/machines/client/auth",
        "sync": f"{api_base_url}/machines/client/sync",
        "config": f"{api_base_url}/machines/client/config?machine_id={machine_id}&token={token}",
        "config_toml": f"{api_base_url}/machines/client/config.toml?machine_id={machine_id}&token={token}",
        "changes": f"{api_base_url}/machines/client/changes?machine_id={machine_id}&token={token}",
        "changes_toml": f"{api_base_url}/machines/client/changes.toml?machine_id={machine_id}&token={token}",
        "log_stream_status": f"{api_base_url}/machines/client/log-stream?machine_id={machine_id}&token={token}",
        "log_stream_upload": f"{api_base_url}/machines/client/logs",
        "legacy_sync": f"{api_base_url}/machines/sync",
        "install_script": f"{machine_api_base_url}/install.sh",
        "bootstrap_script": f"{machine_api_base_url}/install.sh",
        "client_cli": f"{machine_api_base_url}/downloads/porthub",
        "client_script": f"{machine_api_base_url}/client.sh",
        "rathole_x86_64": f"{machine_api_base_url}/downloads/rathole/x86_64",
        "rathole_darwin_x86_64": f"{machine_api_base_url}/downloads/rathole/darwin_x86_64",
        "rathole_arm64": f"{machine_api_base_url}/downloads/rathole/arm64",
        "rathole_armhf": f"{machine_api_base_url}/downloads/rathole/armhf",
        "rathole_armv7": f"{machine_api_base_url}/downloads/rathole/armv7",
        "socket_path": "/socket.io",
    }
    for key in (
        "config",
        "config_toml",
        "changes",
        "changes_toml",
        "install_script",
        "bootstrap_script",
        "client_cli",
        "client_script",
        "rathole_x86_64",
        "rathole_darwin_x86_64",
        "rathole_arm64",
        "rathole_armhf",
        "rathole_armv7",
    ):
        endpoints[key] = _with_client_setup_query(endpoints[key], overrides)
    return endpoints


async def build_machine_config_bundle(
    machine: dict,
    *,
    request: Request | None = None,
) -> dict[str, Any]:
    overrides = get_client_setup_request_overrides(request)
    connections = await load_machine_connections(machine)
    serialized_connections = [
        serialize_machine_connection(connection, machine)
        for connection in connections
    ]
    version = build_machine_config_version(machine, connections)

    return {
        "version": version,
        "machine_id": str(machine["_id"]),
        "machine_name": machine.get("name", ""),
        "hostname": resolve_machine_hostname(machine),
        "enabled": bool(machine.get("enabled", True)),
        "rathole_server_address": get_rathole_server_address(
            request, machine, overrides
        ),
        "service_domain": get_client_setup_service_domain(machine, overrides),
        "connections": serialized_connections,
        "files": {
            "client.toml": render_client_toml(
                machine,
                connections,
                request=request,
                overrides=overrides,
            ),
        },
        "generated_at": datetime.utcnow(),
    }


async def sync_machine_runtime(
    machine: dict,
    *,
    request: Request | None = None,
    hostname: str | None = None,
    local_ip: str | None = None,
    public_ip: str | None = None,
    is_active: bool | None = None,
    client_version: str | None = None,
    client_update_last_handled_request_id: str | None = None,
) -> dict:
    now = datetime.utcnow()
    resolved_public_ip = (
        (public_ip or "").strip()
        or machine.get("public_ip", "")
        or get_request_client_ip(request)
        or ""
    )
    resolved_client_version = (client_version or "").strip()
    client_update_target_version = (machine.get("client_update_target_version") or "").strip()
    resolved_client_update_last_handled_request_id = (
        client_update_last_handled_request_id or ""
    ).strip()
    resolved_client_hostname = (hostname or "").strip()
    resolved_effective_hostname = (
        (machine.get("hostname_override") or "").strip()
        or resolved_client_hostname
        or (machine.get("client_hostname") or "").strip()
        or (machine.get("hostname") or "").strip()
    )
    update_fields: dict[str, Any] = {
        "hostname": resolved_effective_hostname,
        "client_hostname": resolved_client_hostname or (machine.get("client_hostname") or "").strip(),
        "local_ip": (local_ip or "").strip(),
        "public_ip": resolved_public_ip,
        "auth_required": False,
        "last_seen_at": now,
    }

    if resolved_client_update_last_handled_request_id:
        update_fields["client_update_last_handled_request_id"] = (
            resolved_client_update_last_handled_request_id
        )

    if resolved_client_version:
        update_fields["client_version"] = resolved_client_version

        if (
            resolved_client_update_last_handled_request_id
            and resolved_client_update_last_handled_request_id
            == (machine.get("client_update_request_id") or "").strip()
        ):
            update_fields["client_update_target_version"] = ""
            update_fields["client_updated_at"] = now
        elif resolved_client_version == get_latest_client_version():
            update_fields["client_updated_at"] = now

    await db.machines.update_one(
        {"_id": machine["_id"]},
        {"$set": update_fields},
    )

    updated_machine = await db.machines.find_one({"_id": machine["_id"]})
    return updated_machine


async def touch_machine_client_presence(
    machine: dict,
    *,
    request: Request | None = None,
    auth_required: bool = False,
) -> dict:
    now = datetime.utcnow()

    await db.machines.update_one(
        {"_id": machine["_id"]},
        {
            "$set": {
                "auth_required": bool(auth_required),
                "last_seen_at": now,
            }
        },
    )
    return await db.machines.find_one({"_id": machine["_id"]})


async def wait_for_machine_config_change(
    machine_id: str,
    token: str,
    since: str,
    *,
    request: Request | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any] | None:
    wait_timeout = timeout_seconds or MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS
    wait_timeout = max(1, min(wait_timeout, MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS))
    deadline = time.monotonic() + wait_timeout

    while time.monotonic() <= deadline:
        machine = await authenticate_machine(machine_id, token)
        bundle = await build_machine_config_bundle(machine, request=request)
        if bundle["version"] != since:
            return bundle
        await asyncio.sleep(MACHINE_CONFIG_LONG_POLL_INTERVAL_SECONDS)

    return None
