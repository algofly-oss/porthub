import json
import os
import shutil
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import requests
from fastapi import HTTPException

from shared.env import (
    RATHOLE_RELEASE_CACHE_DIR,
    RATHOLE_RELEASE_CACHE_TTL_SECONDS,
    RATHOLE_RELEASE_GITHUB_API_URL,
    RATHOLE_RELEASE_GITHUB_REPOSITORY,
)

_download_locks: dict[str, threading.Lock] = {}

TARGET_ASSET_CANDIDATES = {
    "x86_64": [
        "rathole-x86_64-unknown-linux-gnu.zip",
        "rathole-x86_64-unknown-linux-musl.zip",
    ],
    "darwin_x86_64": [
        "rathole-x86_64-apple-darwin.zip",
    ],
    "arm64": [
        "rathole-aarch64-unknown-linux-musl.zip",
        "rathole-aarch64-unknown-linux-gnu.zip",
    ],
    "armhf": [
        "rathole-arm-unknown-linux-musleabihf.zip",
        "rathole-arm-unknown-linux-gnueabihf.zip",
    ],
    "armv7": [
        "rathole-armv7-unknown-linux-musleabihf.zip",
        "rathole-armv7-unknown-linux-gnueabihf.zip",
    ],
}

TARGET_ALIASES = {
    "amd64": "x86_64",
    "x86": "x86_64",
    "aarch64": "arm64",
    "arm": "armhf",
    "darwin_amd64": "darwin_x86_64",
    "darwin_arm64": "darwin_x86_64",
}


def normalize_target(target: str) -> str:
    normalized = TARGET_ALIASES.get(target, target)
    if normalized not in TARGET_ASSET_CANDIDATES:
        raise HTTPException(status_code=404, detail="Unsupported Rathole target")
    return normalized


def get_cache_root() -> Path:
    configured = (RATHOLE_RELEASE_CACHE_DIR or "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path("/tmp/porthub/rathole-downloads")


def _get_download_lock(target: str) -> threading.Lock:
    if target not in _download_locks:
        _download_locks[target] = threading.Lock()
    return _download_locks[target]


def _http_get_json(url: str) -> dict[str, Any]:
    response = requests.get(
        url,
        headers={"Accept": "application/vnd.github+json"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def get_latest_release_metadata() -> dict[str, Any]:
    repository = RATHOLE_RELEASE_GITHUB_REPOSITORY.strip()
    api_base_url = RATHOLE_RELEASE_GITHUB_API_URL.rstrip("/")
    url = f"{api_base_url}/repos/{repository}/releases/latest"
    try:
        return _http_get_json(url)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to fetch Rathole release metadata: {exc}",
        ) from exc


def _select_asset(release: dict[str, Any], target: str) -> dict[str, Any]:
    candidates = TARGET_ASSET_CANDIDATES[target]
    assets = release.get("assets") or []

    assets_by_name = {asset.get("name"): asset for asset in assets}
    for name in candidates:
        asset = assets_by_name.get(name)
        if asset:
            return asset

    raise HTTPException(
        status_code=502,
        detail=f"No matching Rathole asset found for target {target}",
    )


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _download_asset(archive_url: str, archive_path: Path) -> None:
    response = requests.get(archive_url, stream=True, timeout=120)
    response.raise_for_status()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with archive_path.open("wb") as file_obj:
        for chunk in response.iter_content(chunk_size=1024 * 128):
            if chunk:
                file_obj.write(chunk)


def _extract_binary_from_zip(zip_path: Path, output_path: Path) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        binary_name = None
        for member in archive.namelist():
            if member.endswith("/") or "__MACOSX" in member:
                continue
            candidate = Path(member).name
            if candidate == "rathole":
                binary_name = member
                break

        if binary_name is None:
            raise HTTPException(
                status_code=502,
                detail="Downloaded Rathole archive did not contain the binary",
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(binary_name) as source, output_path.open("wb") as target:
            shutil.copyfileobj(source, target)

    output_path.chmod(output_path.stat().st_mode | 0o755)


def _read_metadata(metadata_path: Path) -> dict[str, Any] | None:
    if not metadata_path.is_file():
        return None
    try:
        return json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _is_cache_valid(binary_path: Path, metadata_path: Path) -> bool:
    if not binary_path.is_file() or not metadata_path.is_file():
        return False
    if RATHOLE_RELEASE_CACHE_TTL_SECONDS <= 0:
        return False
    age_seconds = time.time() - binary_path.stat().st_mtime
    return age_seconds <= RATHOLE_RELEASE_CACHE_TTL_SECONDS


def get_rathole_binary_path(target: str, *, refresh: bool = False) -> Path:
    normalized_target = normalize_target(target)
    cache_root = get_cache_root()
    target_dir = cache_root / normalized_target
    binary_path = target_dir / "rathole"
    metadata_path = target_dir / "metadata.json"

    lock = _get_download_lock(normalized_target)
    with lock:
        if not refresh and _is_cache_valid(binary_path, metadata_path):
            return binary_path

        try:
            release = get_latest_release_metadata()
            asset = _select_asset(release, normalized_target)
            asset_name = asset["name"]
            download_url = asset["browser_download_url"]
        except HTTPException:
            if binary_path.is_file():
                return binary_path
            raise

        target_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir = Path(
            tempfile.mkdtemp(
                prefix=f".rathole-{normalized_target}-",
                dir=target_dir,
            )
        )
        try:
            archive_path = tmp_dir / asset_name
            try:
                _download_asset(download_url, archive_path)
            except requests.RequestException as exc:
                if binary_path.is_file():
                    return binary_path
                raise HTTPException(
                    status_code=502,
                    detail=f"Failed to download Rathole asset: {exc}",
                ) from exc

            extracted_path = tmp_dir / "rathole"
            _extract_binary_from_zip(archive_path, extracted_path)

            os.replace(extracted_path, binary_path)
            _write_text(
                metadata_path,
                json.dumps(
                    {
                        "tag_name": release.get("tag_name"),
                        "asset_name": asset_name,
                        "browser_download_url": download_url,
                        "fetched_at_epoch": int(time.time()),
                    },
                    indent=2,
                ),
            )
            return binary_path
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def get_cached_rathole_metadata(target: str) -> dict[str, Any] | None:
    normalized_target = normalize_target(target)
    return _read_metadata(get_cache_root() / normalized_target / "metadata.json")
