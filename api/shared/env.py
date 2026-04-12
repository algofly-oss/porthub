import os


def _get_optional_int_env(name):
    value = os.environ.get(name)
    if value in (None, ""):
        return None

    try:
        return int(value)
    except ValueError as exc:
        raise BaseException(f"{name} must be an integer") from exc


def _get_bool_env(name, default=False):
    value = os.environ.get(name)
    if value in (None, ""):
        return default

    normalized_value = value.strip().lower()
    if normalized_value in {"1", "true", "yes", "on"}:
        return True

    if normalized_value in {"0", "false", "no", "off"}:
        return False

    raise BaseException(
        f"{name} must be one of: 1, 0, true, false, yes, no, on, off"
    )


def _load_external_port_range():
    start = _get_optional_int_env("EXTERNAL_PORT_RANGE_START")
    end = _get_optional_int_env("EXTERNAL_PORT_RANGE_END")

    if start is None and end is None:
        return None

    if start is None or end is None:
        raise BaseException(
            "EXTERNAL_PORT_RANGE_START and EXTERNAL_PORT_RANGE_END must both be set"
        )

    if start < 1 or start > 65535:
        raise BaseException("EXTERNAL_PORT_RANGE_START must be between 1 and 65535")

    if end < 1 or end > 65535:
        raise BaseException("EXTERNAL_PORT_RANGE_END must be between 1 and 65535")

    if start > end:
        raise BaseException(
            "EXTERNAL_PORT_RANGE_START must be less than or equal to EXTERNAL_PORT_RANGE_END"
        )

    return (start, end)


EXTERNAL_PORT_RANGE = _load_external_port_range()


def get_external_port_range_error_message():
    if EXTERNAL_PORT_RANGE is None:
        return None

    start, end = EXTERNAL_PORT_RANGE
    return f"External port must be between {start} and {end}"


def is_external_port_allowed(port):
    if EXTERNAL_PORT_RANGE is None:
        return True

    start, end = EXTERNAL_PORT_RANGE
    return start <= port <= end

# Load API secret key
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", None)
if API_SECRET_KEY is None:
    raise BaseException("Missing API_SECRET_KEY")

# Load env configuration
API_ALGORITHM = os.environ.get("API_ALGORITHM", "HS256")
API_COOKIES_EXPIRE_MINUTES = int(os.environ.get("API_COOKIES_EXPIRE_MINUTES", 43200))
SIGNUP_DISABLED = _get_bool_env("SIGNUP_DISABLED", False)
RATHOLE_PORT = int(os.environ.get("RATHOLE_PORT", 2334))
MACHINE_ONLINE_TTL_SECONDS = int(os.environ.get("MACHINE_ONLINE_TTL_SECONDS", 300))
MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS = int(
    os.environ.get("MACHINE_CONFIG_LONG_POLL_TIMEOUT_SECONDS", 25)
)
MACHINE_CONFIG_LONG_POLL_INTERVAL_SECONDS = float(
    os.environ.get("MACHINE_CONFIG_LONG_POLL_INTERVAL_SECONDS", 1.0)
)
PORT_HUB_PUBLIC_BASE_URL = os.environ.get("PORT_HUB_PUBLIC_BASE_URL", "")
RATHOLE_SERVER_ADDRESS = os.environ.get("RATHOLE_SERVER_ADDRESS", "")
RATHOLE_RELEASE_GITHUB_REPOSITORY = os.environ.get(
    "RATHOLE_RELEASE_GITHUB_REPOSITORY",
    "rathole-org/rathole",
)
RATHOLE_RELEASE_GITHUB_API_URL = os.environ.get(
    "RATHOLE_RELEASE_GITHUB_API_URL",
    "https://api.github.com",
)
RATHOLE_RELEASE_CACHE_DIR = os.environ.get(
    "RATHOLE_RELEASE_CACHE_DIR",
    "/tmp/porthub/rathole-downloads",
)
RATHOLE_RELEASE_CACHE_TTL_SECONDS = int(
    os.environ.get("RATHOLE_RELEASE_CACHE_TTL_SECONDS", 86400)
)
RATHOLE_DUMMY_SERVICE_NAME = os.environ.get("RATHOLE_DUMMY_SERVICE_NAME", "dummy")
RATHOLE_DUMMY_SERVICE_TOKEN = os.environ.get("RATHOLE_DUMMY_SERVICE_TOKEN", "dummy")
RATHOLE_DUMMY_SERVICE_BIND_ADDR = os.environ.get(
    "RATHOLE_DUMMY_SERVICE_BIND_ADDR",
    "127.0.0.1:65535",
)
RATHOLE_SERVER_CONFIG_PATH = os.environ.get(
    "RATHOLE_SERVER_CONFIG_PATH",
    "/runtime/rathole/server.toml",
)

# Load Redis credentials
REDIS_HOST = os.environ.get("REDIS_HOST", None)
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)

# Load mongodb credentials
MONGO_DATABASE_URI = os.environ.get("MONGO_DATABASE_URI", None)
MONGO_DATABASE_NAME = os.environ.get("MONGO_DATABASE_NAME", None)
