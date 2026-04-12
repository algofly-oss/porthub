from fastapi import APIRouter, Query, Request, Response, status
from pydantic import BaseModel, Field

from shared.client_release import get_client_version as get_latest_client_version
from shared.machine_client import (
    authenticate_machine,
    authenticate_machine_for_logs,
    build_machine_config_bundle,
    build_machine_endpoints,
    sync_machine_runtime,
    touch_machine_client_presence,
    wait_for_machine_config_change,
)
from shared.sockets import (
    CTS_MACHINE_CONFIG_SNAPSHOT,
    STC_MACHINE_CONFIG_CHANGED,
    STC_MACHINE_CONFIG_SNAPSHOT,
    emit_machine_log_lines,
    has_machine_log_stream_subscribers,
    emit_machine_status_changed,
    set_cached_machine_status,
)
from ..common import is_machine_online, serialize_machine

router = APIRouter()


class MachineClientSession(BaseModel):
    machine_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    token: str = Field(..., min_length=1)
    hostname: str | None = Field("", example="luna.local")
    local_ip: str | None = Field("", example="192.168.0.3")
    public_ip: str | None = Field("", example="203.0.113.25")
    is_active: bool | None = Field(True, example=True)
    client_version: str | None = Field("", example="2f41f3d8a1c4")
    client_update_last_handled_request_id: str | None = Field("", example="a1b2c3d4e5f6")


class MachineClientLogBatch(BaseModel):
    machine_id: str = Field(..., example="67f7d26b760bd71f4d3f3c34")
    token: str = Field(..., min_length=1)
    source: str | None = Field("client", example="client")
    lines: list[str] = Field(default_factory=list)


def _apply_client_control_headers(response: Response, machine: dict) -> None:
    latest_client_version = get_latest_client_version()
    machine_client_version = (machine.get("client_version") or "").strip()
    client_update_target_version = (machine.get("client_update_target_version") or "").strip()
    client_update_request_id = (machine.get("client_update_request_id") or "").strip()
    client_update_last_handled_request_id = (
        machine.get("client_update_last_handled_request_id") or ""
    ).strip()

    response.headers["X-PortHub-Client-Latest-Version"] = latest_client_version
    response.headers["X-PortHub-Client-Current-Version"] = machine_client_version
    response.headers["X-PortHub-Client-Update-Requested"] = (
        "true"
        if client_update_request_id
        and client_update_request_id != client_update_last_handled_request_id
        else "false"
    )
    if client_update_target_version:
        response.headers["X-PortHub-Client-Target-Version"] = client_update_target_version
    if client_update_request_id:
        response.headers["X-PortHub-Client-Update-Request-Id"] = client_update_request_id


async def _sync_and_build_session(
    data: MachineClientSession,
    *,
    request: Request,
    response: Response,
    action: str,
):
    machine = await authenticate_machine(data.machine_id, data.token)

    updated_machine = await sync_machine_runtime(
        machine,
        request=request,
        hostname=data.hostname,
        local_ip=data.local_ip,
        public_ip=data.public_ip,
        is_active=data.is_active,
        client_version=data.client_version,
        client_update_last_handled_request_id=data.client_update_last_handled_request_id,
    )

    is_online = is_machine_online(updated_machine)
    updated_serialized_machine = serialize_machine(updated_machine)
    set_cached_machine_status(str(updated_machine["_id"]), is_online)

    response.headers["X-PortHub-Observed-IP"] = updated_serialized_machine["public_ip"]
    _apply_client_control_headers(response, updated_machine)

    # Emit every successful heartbeat so the UI last-seen timestamp stays fresh.
    await emit_machine_status_changed(updated_machine)

    config_bundle = await build_machine_config_bundle(updated_machine, request=request)

    return {
        "msg": f"Machine {action} successfully",
        "data": {
            "machine": updated_serialized_machine,
            "config": config_bundle,
            "endpoints": build_machine_endpoints(updated_machine, request=request),
            "socket_auth": {
                "machine_id": str(updated_machine["_id"]),
                "token": updated_machine["token"],
                "role": "machine",
            },
            "socket": {
                "path": "/socket.io",
                "events": {
                    "request_config_snapshot": CTS_MACHINE_CONFIG_SNAPSHOT,
                    "config_snapshot": STC_MACHINE_CONFIG_SNAPSHOT,
                    "config_changed": STC_MACHINE_CONFIG_CHANGED,
                },
            },
            "polling": {
                "strategy": "long-poll",
                "changes_query_parameter": "since",
            },
            "client": {
                "current_version": updated_serialized_machine.get("client_version", ""),
                "latest_version": updated_serialized_machine.get("latest_client_version", ""),
                "update_requested": updated_serialized_machine.get(
                    "client_update_requested", False
                ),
                "update_target_version": updated_serialized_machine.get(
                    "client_update_target_version", ""
                ),
            },
        },
    }


@router.post("/client/auth")
async def machine_client_auth(data: MachineClientSession, request: Request, response: Response):
    return await _sync_and_build_session(
        data,
        request=request,
        response=response,
        action="authenticated",
    )


@router.post("/client/sync")
async def machine_client_sync(data: MachineClientSession, request: Request, response: Response):
    return await _sync_and_build_session(
        data,
        request=request,
        response=response,
        action="synced",
    )


@router.get("/client/config")
async def machine_client_config(
    request: Request,
    machine_id: str = Query(...),
    token: str = Query(..., min_length=1),
):
    machine = await authenticate_machine(machine_id, token)
    config_bundle = await build_machine_config_bundle(machine, request=request)
    return {
        "msg": "Machine config fetched successfully",
        "data": config_bundle,
    }


@router.get("/client/config.toml")
async def machine_client_config_toml(
    request: Request,
    machine_id: str = Query(...),
    token: str = Query(..., min_length=1),
):
    machine = await authenticate_machine(machine_id, token)
    config_bundle = await build_machine_config_bundle(machine, request=request)
    return Response(
        content=config_bundle["files"]["client.toml"],
        media_type="text/plain",
        headers={
            "Cache-Control": "no-store",
            "X-PortHub-Config-Version": config_bundle["version"],
            "X-PortHub-Machine-Id": str(machine["_id"]),
            "X-PortHub-Client-Latest-Version": get_latest_client_version(),
        },
    )


@router.get("/client/changes")
async def machine_client_changes(
    request: Request,
    machine_id: str = Query(...),
    token: str = Query(..., min_length=1),
    since: str = Query(..., min_length=1),
    wait_seconds: int | None = Query(None, ge=1, le=300),
):
    bundle = await wait_for_machine_config_change(
        machine_id,
        token,
        since,
        request=request,
        timeout_seconds=wait_seconds,
    )

    if bundle is None:
        return {
            "msg": "No machine config changes available",
            "data": {
                "changed": False,
                "version": since,
            },
        }

    return {
        "msg": "Machine config changes fetched successfully",
        "data": {
            "changed": True,
            "config": bundle,
        },
    }


@router.get("/client/changes.toml")
async def machine_client_changes_toml(
    request: Request,
    machine_id: str = Query(...),
    token: str = Query(..., min_length=1),
    since: str = Query(..., min_length=1),
    wait_seconds: int | None = Query(None, ge=1, le=300),
):
    bundle = await wait_for_machine_config_change(
        machine_id,
        token,
        since,
        request=request,
        timeout_seconds=wait_seconds,
    )

    if bundle is None:
        machine = await authenticate_machine(machine_id, token)
        response = Response(
            status_code=status.HTTP_204_NO_CONTENT,
            headers={
                "Cache-Control": "no-store",
                "X-PortHub-Config-Version": since,
                "X-PortHub-Machine-Id": machine_id,
            },
        )
        _apply_client_control_headers(response, machine)
        return response

    machine = await authenticate_machine(machine_id, token)
    response = Response(
        content=bundle["files"]["client.toml"],
        media_type="text/plain",
        headers={
            "Cache-Control": "no-store",
            "X-PortHub-Config-Version": bundle["version"],
            "X-PortHub-Machine-Id": bundle["machine_id"],
        },
    )
    _apply_client_control_headers(response, machine)
    return response


@router.get("/client/log-stream")
async def machine_client_log_stream_status(
    request: Request,
    machine_id: str = Query(...),
    token: str = Query(..., min_length=1),
):
    machine = await authenticate_machine_for_logs(machine_id, token)
    machine = await touch_machine_client_presence(
        machine,
        request=request,
        auth_required=token != machine.get("token"),
    )
    set_cached_machine_status(str(machine["_id"]), is_machine_online(machine))
    await emit_machine_status_changed(machine)
    active = has_machine_log_stream_subscribers(str(machine["_id"]))
    return Response(
        content='{"active":' + ("true" if active else "false") + "}",
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "X-PortHub-Log-Stream-Active": "true" if active else "false",
            "X-PortHub-Machine-Id": str(machine["_id"]),
            "X-PortHub-Machine-Auth-Required": "true"
            if token != machine.get("token")
            else "false",
        },
    )


@router.post("/client/logs")
async def machine_client_logs(data: MachineClientLogBatch, request: Request):
    machine = await authenticate_machine_for_logs(data.machine_id, data.token)
    machine = await touch_machine_client_presence(
        machine,
        request=request,
        auth_required=data.token != machine.get("token"),
    )
    set_cached_machine_status(str(machine["_id"]), is_machine_online(machine))
    await emit_machine_status_changed(machine)
    lines = [
        (line or "").rstrip("\r\n")[:4000]
        for line in (data.lines or [])[:100]
        if (line or "").strip()
    ]

    if lines:
        await emit_machine_log_lines(
            machine,
            lines=lines,
            source=(data.source or "client")[:32],
        )

    return {
        "msg": "Machine logs received successfully",
        "data": {
            "machine_id": str(machine["_id"]),
            "count": len(lines),
        },
    }
