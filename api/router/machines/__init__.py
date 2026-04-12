from fastapi import APIRouter

from .add import router as add_machine_router
from .command import router as command_machine_router
from .client import router as client_machine_router
from .delete import router as delete_machine_router
from .list import router as list_machine_router
from .refresh_token import router as refresh_machine_token_router
from .request_client_update import router as request_client_update_machine_router
from .sync import router as sync_machine_router
from .update import router as update_machine_router

router = APIRouter(
    prefix="/machines",
    tags=["Machines"],
)

router.include_router(add_machine_router)
router.include_router(update_machine_router)
router.include_router(list_machine_router)
router.include_router(delete_machine_router)
router.include_router(refresh_machine_token_router)
router.include_router(request_client_update_machine_router)
router.include_router(sync_machine_router)
router.include_router(command_machine_router)
router.include_router(client_machine_router)
