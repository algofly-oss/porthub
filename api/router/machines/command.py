import asyncio
import hashlib
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse

from shared.factory import db
from shared.machine_client import (
    authenticate_machine,
    authenticate_machine_for_logs,
    build_machine_endpoints,
    get_api_base_url,
)
from shared.rathole_release import get_cached_rathole_metadata, get_rathole_binary_path, normalize_target
from ..common import (
    get_authenticated_user,
    parse_object_id,
    serialize_machine,
)

router = APIRouter()

ASSETS_DIR = Path(__file__).resolve().parents[2] / "client"
SCRIPT_ASSET_FILENAMES = {
    "install": "install.sh",
    "client": "porthub-client.sh",
}


def get_asset_path(filename: str) -> Path:
    asset_path = ASSETS_DIR / filename
    if not asset_path.is_file():
        raise HTTPException(status_code=404, detail=f"Asset not found: {filename}")
    return asset_path


def get_asset_version(filename: str) -> str:
    return hashlib.sha256(get_asset_path(filename).read_bytes()).hexdigest()[:12]

def render_script_asset(script_name: str, request: Request, machine: dict) -> str:
    filename = SCRIPT_ASSET_FILENAMES.get(script_name)
    if not filename:
        raise HTTPException(status_code=404, detail="Unsupported script asset")

    endpoints = build_machine_endpoints(machine, request=request)
    replacements = {
        "__PORT_HUB_CLIENT_VERSION__": get_asset_version(filename),
        "__PORT_HUB_API_URL__": get_api_base_url(request),
        "__PORT_HUB_MACHINE_ID__": str(machine["_id"]),
        "__PORT_HUB_MACHINE_TOKEN__": machine["token"],
        "__PORT_HUB_AUTH_URL__": endpoints["auth"],
        "__PORT_HUB_SYNC_URL__": endpoints["sync"],
        "__PORT_HUB_CONFIG_TOML_URL__": endpoints["config_toml"],
        "__PORT_HUB_CHANGES_TOML_URL__": endpoints["changes_toml"],
        "__PORT_HUB_LOG_STREAM_STATUS_URL__": endpoints["log_stream_status"],
        "__PORT_HUB_LOG_STREAM_UPLOAD_URL__": endpoints["log_stream_upload"],
        "__PORT_HUB_RATHOLE_X86_64_URL__": endpoints["rathole_x86_64"],
        "__PORT_HUB_RATHOLE_DARWIN_X86_64_URL__": endpoints["rathole_darwin_x86_64"],
        "__PORT_HUB_RATHOLE_ARM64_URL__": endpoints["rathole_arm64"],
        "__PORT_HUB_RATHOLE_ARMHF_URL__": endpoints["rathole_armhf"],
        "__PORT_HUB_RATHOLE_ARMV7_URL__": endpoints["rathole_armv7"],
        "__PORT_HUB_CLI_URL__": endpoints["client_cli"],
    }

    content = get_asset_path(filename).read_text(encoding="utf-8")
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    return content


def build_install_command(request: Request, machine: dict) -> str:
    endpoints = build_machine_endpoints(machine, request=request)
    return (
        f"curl -fsSL {endpoints['install_script']} -o install.sh "
        "&& chmod +x install.sh "
        "&& ./install.sh "
        "&& porthub status"
    )


@router.get("/command/{machine_id}")
async def machine_command(machine_id: str, request: Request):
    user = await get_authenticated_user(request)
    machine = await db.machines.find_one(
        {"_id": parse_object_id(machine_id, "Invalid machine id"), "user_id": user["_id"]}
    )

    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    return {
        "msg": "Machine command generated successfully",
        "data": {
            "machine": serialize_machine(machine),
            "command": build_install_command(request, machine),
        },
    }


@router.get("/{machine_id}/{token}/install.sh")
async def machine_install_script(machine_id: str, token: str, request: Request):
    machine = await authenticate_machine_for_logs(machine_id, token)
    return Response(
        content=render_script_asset("install", request, machine),
        media_type="text/plain",
    )


@router.get("/{machine_id}/{token}/client.sh")
async def machine_client_script(machine_id: str, token: str, request: Request):
    machine = await authenticate_machine_for_logs(machine_id, token)
    return Response(
        content=render_script_asset("client", request, machine),
        media_type="text/plain",
    )


@router.get("/{machine_id}/{token}/downloads/porthub")
async def machine_cli_download(machine_id: str, token: str, request: Request):
    machine = await authenticate_machine_for_logs(machine_id, token)
    return Response(
        content=render_script_asset("client", request, machine),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="porthub"',
        },
    )


@router.get("/{machine_id}/{token}/downloads/rathole/{target}")
async def machine_rathole_download(machine_id: str, token: str, target: str):
    await authenticate_machine(machine_id, token)
    normalized_target = normalize_target(target)
    asset_path = await asyncio.to_thread(get_rathole_binary_path, normalized_target)
    metadata = get_cached_rathole_metadata(normalized_target) or {}
    return FileResponse(
        asset_path,
        media_type="application/octet-stream",
        filename="rathole",
        headers={
            "Cache-Control": "no-store",
            "X-PortHub-Rathole-Target": normalized_target,
            "X-PortHub-Rathole-Release": metadata.get("tag_name", ""),
            "X-PortHub-Rathole-Asset": metadata.get("asset_name", ""),
        },
    )
