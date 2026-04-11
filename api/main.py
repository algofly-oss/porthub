import logging
import asyncio

from fastapi import FastAPI, WebSocket
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from router import ping, auth, connections, machines
from shared.rathole_config import get_server_toml_path, is_dummy_only_config, rebuild_server_toml
from sockets import sio_app

API_ROOT = "/api"
logger = logging.getLogger(__name__)
STARTUP_REBUILD_DELAYS_SECONDS = (0, 2, 5, 10, 20)
POST_STARTUP_REBUILD_DELAYS_SECONDS = (30, 60, 120)
retry_task = None


async def attempt_rathole_config_rebuild(*, context: str, delays: tuple[int, ...]) -> bool:
    for attempt, delay_seconds in enumerate(delays, start=1):
        if delay_seconds > 0:
            await asyncio.sleep(delay_seconds)

        try:
            path = await rebuild_server_toml()
            content = path.read_text(encoding="utf-8")
        except Exception:
            logger.exception(
                "Failed to rebuild Rathole server.toml during %s attempt %s",
                context,
                attempt,
            )
            continue

        if not is_dummy_only_config(content):
            logger.warning(
                "Rathole server.toml rebuilt during %s attempt %s at %s",
                context,
                attempt,
                path,
            )
            return True

        logger.warning(
            "Rathole server.toml still dummy-only during %s attempt %s; delay=%ss",
            context,
            attempt,
            delay_seconds,
        )

    return False


async def retry_rathole_config_rebuild() -> None:
    rebuilt = await attempt_rathole_config_rebuild(
        context="post-startup retry",
        delays=POST_STARTUP_REBUILD_DELAYS_SECONDS,
    )
    if not rebuilt:
        logger.warning(
            "Rathole server.toml remained dummy-only after post-startup retries at %s",
            get_server_toml_path(),
        )


async def handle_startup() -> None:
    global retry_task
    rebuilt = await attempt_rathole_config_rebuild(
        context="startup",
        delays=STARTUP_REBUILD_DELAYS_SECONDS,
    )
    if not rebuilt:
        logger.warning(
            "Continuing API startup with dummy-only Rathole config; background retries will continue for %s",
            get_server_toml_path(),
        )
        retry_task = asyncio.create_task(retry_rathole_config_rebuild())


async def handle_shutdown() -> None:
    global retry_task
    if retry_task is not None:
        retry_task.cancel()
        retry_task = None


app = FastAPI(
    title="PortHub API",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    version="0.1.0",
    docs_url=f"{API_ROOT}/docs",
    openapi_url=f"{API_ROOT}/openapi.json",
)

# app.mount('/socket', app=sio_app)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# Redirect root to docs
@app.get(API_ROOT, include_in_schema=False)
async def root():
    return RedirectResponse(f"{API_ROOT}/docs")


app.add_event_handler("startup", handle_startup)
app.add_event_handler("shutdown", handle_shutdown)


app.include_router(ping.router, prefix=API_ROOT)
app.include_router(auth.router, prefix=API_ROOT)
app.include_router(machines.router, prefix=API_ROOT)
app.include_router(connections.router, prefix=API_ROOT)
