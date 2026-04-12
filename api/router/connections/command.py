from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.get("/command/{_id}")
async def connection_command(_id: str):
    raise HTTPException(
        status_code=410,
        detail="Per-connection client scripts are deprecated. Use the machine bootstrap endpoint instead.",
    )
