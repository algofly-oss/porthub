from fastapi import APIRouter
from .add import router as add_connection_router
from .list import router as list_connections_router
from .update import router as update_connection_router
from .delete import router as delete_connection_router
from .command import router as command_connection_router

router = APIRouter(
    prefix="/connections",
    tags=["Connections"],
)

router.include_router(add_connection_router)
router.include_router(update_connection_router)
router.include_router(list_connections_router)
router.include_router(delete_connection_router)
router.include_router(command_connection_router)

