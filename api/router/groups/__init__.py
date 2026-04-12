from fastapi import APIRouter

from .add import router as add_group_router
from .list import router as list_groups_router
from .update import router as update_group_router
from .delete import router as delete_group_router

router = APIRouter(
    prefix="/groups",
    tags=["Machine groups"],
)

router.include_router(add_group_router)
router.include_router(list_groups_router)
router.include_router(update_group_router)
router.include_router(delete_group_router)
