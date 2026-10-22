"""Isolated overlay test controller. Never include this app in production.

The runner supplies a fresh database name and random admin secret. Only the two
real credential-authenticated native endpoints are accessible without that key.
"""
import os
import re
from datetime import datetime

from bson import ObjectId
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from router import access
from router.access import private
from shared import factory, workspaces

name = os.environ["PORTHUB_OVERLAY_LAB_DATABASE"]
if not re.fullmatch(r"porthub_overlay_lab_[a-f0-9]{16}", name):
    raise RuntimeError("Refusing a non-lab database")
secret = os.environ["PORTHUB_OVERLAY_LAB_SECRET"]
if len(secret) < 32:
    raise RuntimeError("A random lab administrator secret is required")
db = factory.db.client[name]
private.db = access.db = workspaces.db = db
owner, group_a, group_b, machine_a, machine_b, machine_c = [ObjectId() for _ in range(6)]
MACHINES = {"a": machine_a, "b": machine_b, "c": machine_c}
app = FastAPI()
app.include_router(private.router, prefix="/api/access")


async def context(request, manage=False):
    return {"_id": owner}, owner, "owner"
private.browser_context = context


@app.middleware("http")
async def guard(request: Request, call_next):
    public = request.url.path in {"/api/access/private/bootstrap", "/api/access/private/sync"}
    if not public and request.headers.get("x-lab-key") != secret:
        return JSONResponse({"detail": "Lab administrator key required"}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
async def startup():
    await db.users.insert_one({"_id": owner, "name": "Overlay test owner", "role": "user"})
    await db.machine_groups.insert_many([
        {"_id": group_a, "user_id": owner, "name": "Test source"},
        {"_id": group_b, "user_id": owner, "name": "Test destination"},
    ])
    await db.machines.insert_many([
        {"_id": machine_a, "user_id": owner, "name": "lab-a", "group_ids": [group_a], "enabled": True},
        {"_id": machine_b, "user_id": owner, "name": "lab-b", "group_ids": [group_b], "enabled": True},
        # Optional third machine, also a destination (for multi-host tests).
        {"_id": machine_c, "user_id": owner, "name": "lab-c", "group_ids": [group_b], "enabled": True},
    ])


@app.on_event("shutdown")
async def shutdown():
    # This exact per-run database was created by this process; no app DB touched.
    if re.fullmatch(r"porthub_overlay_lab_[a-f0-9]{16}", name):
        await factory.db.client.drop_database(name)


@app.get("/lab/state")
async def state():
    peers = await db.private_peers.find({}, {"_id": 1, "ip": 1, "paths": 1, "last_seen_at": 1, "revision": 1}).to_list(None)
    return {"machines": {k: str(v) for k, v in MACHINES.items()}, "peers": peers,
            "public_ports": await db.connections.count_documents({}),
            "public_proxies": await db.traffic_routes.count_documents({})}


@app.post("/lab/enroll/{which}")
async def enroll(which: str, request: Request):
    if which not in MACHINES:
        raise HTTPException(404)
    return await private.enroll_peer(private.PeerEnrollment(machine_id=str(MACHINES[which]), alias=f"lab-{which}"), request)


@app.put("/lab/policy")
async def policy(body: dict):
    await db.access_rulebooks.delete_many({})
    if body.get("enabled", False):
        await db.access_rulebooks.insert_one({
            "name": "Lab private policy", "user_id": owner, "group_id": str(group_a), "enabled": True,
            "rules": [{"id": "test-rule", "name": "Test traffic", "enabled": True,
                       "sources": [{"kind": "group", "id": str(group_a)}],
                       "destinations": [{"kind": "group", "id": str(group_b)}],
                       "protocol": body.get("protocol", "tcp"), "ports": body.get("ports", "18080"),
                       "bidirectional": body.get("bidirectional", False)}],
            "created_at": datetime.utcnow(),
        })
    return {"saved": True}
