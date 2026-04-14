import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from router import ping, ports
from shared.db import init_db, load_state
from shared.env import API_ROOT
from shared.nft import apply_rules
from shared.sampler import db_writer, traffic_loop
from shared.state import STATE

logger = logging.getLogger(__name__)
sampler_task = None
db_writer_task = None


async def handle_startup() -> None:
    global sampler_task, db_writer_task
    await init_db()

    restored_state = await load_state()
    STATE.clear()
    STATE.update(restored_state)
    apply_rules(STATE)

    sampler_task = asyncio.create_task(traffic_loop())
    db_writer_task = asyncio.create_task(db_writer())
    logger.info("Firewall service started with %s persisted port policies", len(STATE))


async def handle_shutdown() -> None:
    global sampler_task, db_writer_task
    for task in (sampler_task, db_writer_task):
        if task is not None:
            task.cancel()

    sampler_task = None
    db_writer_task = None


app = FastAPI(
    title="PortHub Firewall API",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    version="0.1.0",
    docs_url=f"{API_ROOT}/docs",
    openapi_url=f"{API_ROOT}/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


@app.get(API_ROOT, include_in_schema=False)
async def root():
    return RedirectResponse(f"{API_ROOT}/docs")


app.add_event_handler("startup", handle_startup)
app.add_event_handler("shutdown", handle_shutdown)

app.include_router(ping.router, prefix=API_ROOT)
app.include_router(ports.router, prefix=API_ROOT)
