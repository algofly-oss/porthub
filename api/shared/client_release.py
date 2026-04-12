import hashlib
from pathlib import Path


CLIENT_ASSETS_DIR = Path(__file__).resolve().parents[1] / "client"
CLIENT_SCRIPT_FILENAME = "porthub-client.sh"


def get_client_script_path() -> Path:
    asset_path = CLIENT_ASSETS_DIR / CLIENT_SCRIPT_FILENAME
    if not asset_path.is_file():
        raise FileNotFoundError(f"PortHub client asset not found: {asset_path}")
    return asset_path


def get_client_version() -> str:
    return hashlib.sha256(get_client_script_path().read_bytes()).hexdigest()[:12]
