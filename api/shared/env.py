import os

# Load API secret key
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", None)
if API_SECRET_KEY is None:
    raise BaseException("Missing API_SECRET_KEY")

# Load env configuration
API_ALGORITHM = os.environ.get("API_ALGORITHM", "HS256")
API_COOKIES_EXPIRE_MINUTES = int(os.environ.get("API_COOKIES_EXPIRE_MINUTES", 43200))
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
