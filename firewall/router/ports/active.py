from fastapi import APIRouter, Depends

from router.auth import require_key
from shared.state import ACTIVE_PORTS

router = APIRouter()


@router.get("/active", dependencies=[Depends(require_key)])
async def active_ports():
    return {
        "msg": "Active ports listed successfully",
        "data": [
            {"port": port, "last_seen": last_seen}
            for port, last_seen in sorted(ACTIVE_PORTS.items())
        ],
    }
