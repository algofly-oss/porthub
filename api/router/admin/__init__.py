from fastapi import APIRouter

from .overview import router as overview_router

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
)

router.include_router(overview_router)
