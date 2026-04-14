from fastapi import APIRouter

from .active import router as active_router
from .policy import router as policy_router
from .recent import router as recent_router
from .traffic import router as traffic_router

router = APIRouter(
    prefix="/ports",
    tags=["Ports"],
)

router.include_router(policy_router)
router.include_router(active_router)
router.include_router(recent_router)
router.include_router(traffic_router)
