from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db
from bson import ObjectId
from ..auth.common import authenticate_user
import pydantic

router = APIRouter()

class DeleteConnection(pydantic.BaseModel):
    data_id: str

@router.post("/delete")
async def delete_connection(data: DeleteConnection, request: Request):
    # Check if user is logged in
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    # Check if connection already exists
    connection = await db.connections.find_one(
        {"_id": ObjectId(data.data_id), "user_id": user["_id"]}
    )
    if not connection:
        raise HTTPException(status_code=400, detail="Connection not found")

    # Delete connection
    await db.connections.delete_one({"_id": connection["_id"]})

    return {
        "msg": "Connection deleted successfully",
    }
