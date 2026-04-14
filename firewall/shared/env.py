import os


def _get_required_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise BaseException(f"Missing {name}")
    return value


def _get_int_env(name: str, default: int) -> int:
    value = (os.getenv(name) or "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise BaseException(f"{name} must be an integer") from exc


API_ROOT = os.getenv("FW_API_ROOT", "/api").rstrip("/") or "/api"
API_KEY = _get_required_env("FW_API_KEY")
DB_PATH = os.getenv("FW_DB_PATH", "/state/firewall.db")
BUFFER_SECONDS = _get_int_env("FW_BUFFER_SECONDS", 300)
ACTIVE_TTL = _get_int_env("FW_ACTIVE_TTL", 300)
RECENT_IP_TTL = _get_int_env("FW_RECENT_IP_TTL", 300)
RECENT_IP_HISTORY_LIMIT = _get_int_env("FW_RECENT_IP_HISTORY_LIMIT", 10)
NFT_TABLE = os.getenv("FW_NFT_TABLE", "inet rathole")
HOST = os.getenv("FW_HOST", "0.0.0.0")
PORT = _get_int_env("FW_PORT", 8001)
NUM_WORKERS = _get_int_env("FW_NUM_WORKERS", 2)
