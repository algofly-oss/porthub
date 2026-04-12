import logging
import asyncio
import socketio

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from router import ping, auth, connections, groups, machines
from shared.rathole_config import (
    get_server_toml_path,
    is_dummy_only_config,
    rebuild_server_toml,
)
from shared.sockets import initialize_machine_status_cache, monitor_machine_statuses, sio

API_ROOT = "/api"
logger = logging.getLogger(__name__)
STARTUP_REBUILD_DELAYS_SECONDS = (0, 2, 5, 10, 20)
POST_STARTUP_REBUILD_DELAYS_SECONDS = (30, 60, 120)
retry_task = None
machine_status_monitor_task = None
machine_status_monitor_stop_event = None


class QuietMachineClientAccessFilter(logging.Filter):
    QUIET_PATHS = {
        "/api/machines/client/auth",
        "/api/machines/client/sync",
        "/api/machines/client/config",
        "/api/machines/client/config.toml",
        "/api/machines/client/changes",
        "/api/machines/client/changes.toml",
        "/api/machines/client/log-stream",
        "/api/machines/client/logs",
    }

    def filter(self, record: logging.LogRecord) -> bool:
        args = getattr(record, "args", ())
        if not isinstance(args, tuple) or len(args) < 5:
            return True

        path = str(args[2] or "").split("?", 1)[0]

        try:
            status_code = int(args[4])
        except (TypeError, ValueError):
            return True

        if path in self.QUIET_PATHS and status_code < 400:
            return False

        return True


def configure_access_log_filters() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    if any(
        isinstance(filter_, QuietMachineClientAccessFilter)
        for filter_ in access_logger.filters
    ):
        return
    access_logger.addFilter(QuietMachineClientAccessFilter())


configure_access_log_filters()


async def attempt_rathole_config_rebuild(
    *, context: str, delays: tuple[int, ...]
) -> bool:
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
    global retry_task, machine_status_monitor_task, machine_status_monitor_stop_event
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

    await initialize_machine_status_cache()
    machine_status_monitor_stop_event = asyncio.Event()
    machine_status_monitor_task = asyncio.create_task(
        monitor_machine_statuses(machine_status_monitor_stop_event)
    )


async def handle_shutdown() -> None:
    global retry_task, machine_status_monitor_task, machine_status_monitor_stop_event
    if retry_task is not None:
        retry_task.cancel()
        retry_task = None

    if machine_status_monitor_stop_event is not None:
        machine_status_monitor_stop_event.set()
        machine_status_monitor_stop_event = None

    if machine_status_monitor_task is not None:
        machine_status_monitor_task.cancel()
        machine_status_monitor_task = None


fastapi_app = FastAPI(
    title="PortHub API",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    version="0.1.0",
    docs_url=f"{API_ROOT}/docs",
    openapi_url=f"{API_ROOT}/openapi.json",
)

# Add CORS middleware
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# Redirect root to docs
@fastapi_app.get(API_ROOT, include_in_schema=False)
async def root():
    return RedirectResponse(f"{API_ROOT}/docs")


fastapi_app.add_event_handler("startup", handle_startup)
fastapi_app.add_event_handler("shutdown", handle_shutdown)

fastapi_app.include_router(ping.router, prefix=API_ROOT)
fastapi_app.include_router(auth.router, prefix=API_ROOT)
fastapi_app.include_router(groups.router, prefix=API_ROOT)
fastapi_app.include_router(machines.router, prefix=API_ROOT)
fastapi_app.include_router(connections.router, prefix=API_ROOT)

app = socketio.ASGIApp(
    socketio_server=sio,
    other_asgi_app=fastapi_app,
    socketio_path="socket.io",
)
