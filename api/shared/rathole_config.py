import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from shared.env import (
    RATHOLE_DUMMY_SERVICE_BIND_ADDR,
    RATHOLE_DUMMY_SERVICE_NAME,
    RATHOLE_DUMMY_SERVICE_TOKEN,
    RATHOLE_PORT,
    RATHOLE_SERVER_CONFIG_PATH,
)
from shared.factory import get_db

logger = logging.getLogger(__name__)

DEFAULT_SERVER_TOML_PATH = (
    Path(__file__).resolve().parent.parent / ".runtime" / "rathole" / "server.toml"
)
SERVICE_KEY_PATTERN = re.compile(r"[^a-zA-Z0-9_]+")
MANAGED_HEADER = "# Managed by PortHub. Manual changes will be overwritten."
TEMP_FILE_PREFIX = ".server.toml.tmp-"


def get_server_toml_path() -> Path:
    configured_path = (RATHOLE_SERVER_CONFIG_PATH or "").strip()
    if configured_path:
        return Path(configured_path).expanduser()
    return DEFAULT_SERVER_TOML_PATH


def build_service_key(connection: dict) -> str:
    connection_id = str(connection.get("_id", "service"))
    sanitized_id = SERVICE_KEY_PATTERN.sub("_", connection_id).strip("_") or "service"
    return f"porthub_{connection.get('external_port', 'port')}_{sanitized_id}"


def render_server_toml(services: list[dict], source: str) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        MANAGED_HEADER,
        f"# source: {source}",
        f"# generated_at_utc: {generated_at}",
        f"# services_count: {len(services)}",
        "[server]",
        f'bind_addr = "0.0.0.0:{RATHOLE_PORT}"',
        "",
        f"[server.services.{RATHOLE_DUMMY_SERVICE_NAME}]",
        f'token = "{RATHOLE_DUMMY_SERVICE_TOKEN}"',
        f'bind_addr = "{RATHOLE_DUMMY_SERVICE_BIND_ADDR}"',
        "",
    ]

    for service in services:
        lines.extend(
            [
                f"[server.services.{service['key']}]",
                f'token = "{service["token"]}"',
                f'bind_addr = "0.0.0.0:{service["external_port"]}"',
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def write_server_toml(content: str) -> Path:
    target_path = get_server_toml_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists() and target_path.is_dir():
        raise IsADirectoryError(
            f"Rathole config target must be a file, but is a directory: {target_path}"
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
        return target_path
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to clean up temp Rathole config %s", temp_path)
        raise


def write_base_server_toml() -> Path:
    path = write_server_toml(render_server_toml([], source="bootstrap"))
    logger.warning("Wrote bootstrap Rathole server config to %s", path)
    return path


def is_dummy_only_config(content: str) -> bool:
    return "[server.services.dummy]" in content and "[server.services.porthub_" not in content


async def rebuild_server_toml(*, allow_empty: bool = False) -> Path:
    db = get_db()
    machines = await db.machines.find(
        {
            "token": {"$nin": [None, ""]},
        }
    ).to_list(length=None)
    machines_by_id = {machine["_id"]: machine for machine in machines}

    services = []
    if machines_by_id:
        connections = (
            await db.connections.find(
                {
                    "enabled": {"$ne": False},
                    "machine_id": {"$in": list(machines_by_id.keys())},
                }
            )
            .sort([("external_port", 1), ("_id", 1)])
            .to_list(length=None)
        )

        for connection in connections:
            machine = machines_by_id.get(connection.get("machine_id"))
            if not machine:
                continue

            services.append(
                {
                    "key": build_service_key(connection),
                    "token": machine["token"],
                    "external_port": connection["external_port"],
                }
            )

    target_path = get_server_toml_path()
    if not services and not allow_empty and target_path.exists():
        existing_content = target_path.read_text(encoding="utf-8")
        if not is_dummy_only_config(existing_content):
            logger.warning(
                "Skipping dummy-only Rathole rewrite because an existing real config is present at %s",
                target_path,
            )
            return target_path

    path = write_server_toml(render_server_toml(services, source="database-rebuild"))
    logger.warning("Rebuilt Rathole server config with %s services at %s", len(services), path)
    return path
