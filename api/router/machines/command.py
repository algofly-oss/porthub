from fastapi import APIRouter, HTTPException, Request, Response

from shared.factory import db
from ..common import (
    get_authenticated_user,
    parse_object_id,
    serialize_machine,
)

router = APIRouter()


def build_client_script(request: Request, machine: dict) -> str:
    base_url = str(request.base_url).rstrip("/")
    machine_id = str(machine["_id"])
    token = machine["token"]

    return f"""#!/usr/bin/env bash
set -euo pipefail

PORT_HUB_API_URL="{base_url}"
PORT_HUB_MACHINE_ID="{machine_id}"
PORT_HUB_MACHINE_TOKEN="{token}"

sudo mkdir -p /etc/porthub
sudo tee /etc/porthub/client.env > /dev/null <<EOF
PORT_HUB_API_URL=$PORT_HUB_API_URL
PORT_HUB_MACHINE_ID=$PORT_HUB_MACHINE_ID
PORT_HUB_MACHINE_TOKEN=$PORT_HUB_MACHINE_TOKEN
EOF

echo "PortHub machine bootstrap complete."
echo "Saved machine credentials to /etc/porthub/client.env."
echo "The client should POST hostname, local_ip, and public_ip to $PORT_HUB_API_URL/api/machines/sync."
echo "Install and launch the Rathole client from this file once the infrastructure is ready."
"""


@router.get("/command/{machine_id}")
async def machine_command(machine_id: str, request: Request):
    user = await get_authenticated_user(request)
    machine = await db.machines.find_one(
        {"_id": parse_object_id(machine_id, "Invalid machine id"), "user_id": user["_id"]}
    )

    if not machine:
        raise HTTPException(status_code=400, detail="Machine not found")

    base_url = str(request.base_url).rstrip("/")
    script_url = f"{base_url}/api/machines/{machine_id}/{machine['token']}/client.sh"

    return {
        "msg": "Machine command generated successfully",
        "data": {
            "machine": serialize_machine(machine),
            "command": f"curl -fsSL {script_url} -o porthub-client.sh && chmod +x porthub-client.sh && ./porthub-client.sh",
        },
    }


@router.get("/{machine_id}/{token}/client.sh")
async def machine_client_script(machine_id: str, token: str, request: Request):
    machine = await db.machines.find_one(
        {
            "_id": parse_object_id(machine_id, "Invalid machine id"),
            "token": token,
        }
    )
    if not machine:
        return Response(content='echo "403 Not Authenticated"\n', media_type="text/plain")

    return Response(content=build_client_script(request, machine), media_type="text/plain")
