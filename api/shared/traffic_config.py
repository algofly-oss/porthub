import json
import ipaddress
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from shared.env import TRAEFIK_DYNAMIC_CONFIG_PATH
from shared.factory import get_db

logger = logging.getLogger(__name__)

DEFAULT_TRAFFIC_CONFIG_PATH = Path("/runtime/traefik/traffic-routes.yml")
MANAGED_HEADER = "# Managed by PortHub. Manual changes will be overwritten."
TEMP_FILE_PREFIX = ".traffic-routes.yml.tmp-"
ROUTE_KEY_PATTERN = re.compile(r"[^a-zA-Z0-9_]+")


def get_traffic_config_path() -> Path:
    configured_path = (TRAEFIK_DYNAMIC_CONFIG_PATH or "").strip()
    if configured_path:
        return Path(configured_path).expanduser()
    return DEFAULT_TRAFFIC_CONFIG_PATH


def build_route_key(route: dict) -> str:
    route_id = str(route.get("_id", "route"))
    sanitized_id = ROUTE_KEY_PATTERN.sub("_", route_id).strip("_") or "route"
    return f"porthub_traffic_{sanitized_id}"


def serialize_traffic_route_document(route: dict) -> dict:
    return {
        "_id": str(route["_id"]),
        "user_id": str(route["user_id"]),
        "name": (route.get("name") or "").strip(),
        "description": (route.get("description") or "").strip(),
        "hosts": [str(host).strip().lower() for host in (route.get("hosts") or []) if str(host).strip()],
        "target_mode": (route.get("target_mode") or "manual").strip() or "manual",
        "target_url": (route.get("target_url") or "").strip(),
        "enabled": route.get("enabled", True) is not False,
        "entry_points": [
            str(entry_point).strip()
            for entry_point in (route.get("entry_points") or [])
            if str(entry_point).strip()
        ] or ["web"],
        "connection": route.get("connection") or None,
        "created_at": route.get("created_at"),
        "updated_at": route.get("updated_at"),
    }


def _yaml_scalar(value: str) -> str:
    return json.dumps(value)


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def should_disable_pass_host_header(route: dict) -> bool:
    if (route.get("target_mode") or "").strip().lower() != "manual":
        return False

    target_url = str(route.get("target_url") or "").strip()
    if not target_url:
        return False

    parsed = urlsplit(target_url)
    target_host = (parsed.hostname or "").strip().lower()
    if not target_host or _is_ip_host(target_host):
        return False

    route_hosts = {
        str(host).strip().lower()
        for host in (route.get("hosts") or [])
        if str(host).strip()
    }
    return target_host not in route_hosts


def render_traffic_config(routes: list[dict], source: str) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        MANAGED_HEADER,
        f"# source: {source}",
        f"# generated_at_utc: {generated_at}",
        f"# routes_count: {len(routes)}",
    ]

    if not routes:
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(
        [
            "http:",
            "  routers:",
        ]
    )

    for route in routes:
        route_key = build_route_key(route)
        hosts = route["hosts"]
        host_rule = "Host(" + ",".join(f"`{host}`" for host in hosts) + ")"
        lines.extend(
            [
                f"    {route_key}:",
                "      entryPoints:",
            ]
        )
        for entry_point in route["entry_points"]:
            lines.append(f"        - {_yaml_scalar(entry_point)}")
        lines.extend(
            [
                f"      rule: {_yaml_scalar(host_rule)}",
                f"      service: {_yaml_scalar(route_key)}",
            ]
        )

    lines.append("  services:")
    for route in routes:
        route_key = build_route_key(route)
        lines.extend(
            [
                f"    {route_key}:",
                "      loadBalancer:",
                f"        passHostHeader: {'false' if should_disable_pass_host_header(route) else 'true'}",
                "        servers:",
                f"          - url: {_yaml_scalar(route['target_url'])}",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def write_traffic_config(content: str) -> Path:
    target_path = get_traffic_config_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists() and target_path.is_dir():
        raise IsADirectoryError(
            f"Traefik dynamic config target must be a file, but is a directory: {target_path}"
        )

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=target_path.parent,
            prefix=TEMP_FILE_PREFIX,
            delete=False,
        ) as temp_file:
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        os.replace(temp_path, target_path)
        target_path.touch()
        target_path.parent.touch()
        return target_path
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to clean up temp Traefik config %s", temp_path)
        raise


def write_base_traffic_config() -> Path:
    path = write_traffic_config(render_traffic_config([], source="bootstrap"))
    logger.warning("Wrote bootstrap Traefik traffic config to %s", path)
    return path


async def rebuild_traffic_config() -> Path:
    db = get_db()
    routes = (
        await db.traffic_routes.find({"enabled": {"$ne": False}})
        .sort([("created_at", 1), ("_id", 1)])
        .to_list(length=None)
    )
    serialized_routes = [serialize_traffic_route_document(route) for route in routes]
    path = write_traffic_config(
        render_traffic_config(serialized_routes, source="database-rebuild")
    )
    logger.warning("Rebuilt Traefik traffic config with %s routes at %s", len(serialized_routes), path)
    return path
