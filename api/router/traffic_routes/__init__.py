from fastapi import APIRouter

from .add import router as add_traffic_route_router
from .delete import router as delete_traffic_route_router
from .list import router as list_traffic_route_router
from .update import router as update_traffic_route_router

router = APIRouter(
    prefix="/traffic-routes",
    tags=["Traffic Routes"],
)

router.include_router(add_traffic_route_router)
router.include_router(update_traffic_route_router)
router.include_router(list_traffic_route_router)
router.include_router(delete_traffic_route_router)
