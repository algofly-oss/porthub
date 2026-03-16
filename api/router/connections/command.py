import os
from fastapi import APIRouter, Request, Response, HTTPException
from shared.factory import db, redis
from bson import ObjectId
from ..auth.common import authenticate_user

router = APIRouter()

@router.get("/command/{_id}")
async def connection_command(_id: str, request: Request, response: Response):
    # Check if user is logged in
    user_id = authenticate_user(request.cookies.get("session_token"))
    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})
    if not user:
        raise HTTPException(status_code=400, detail="User not logged in")

    data = await db.connections.find_one({"_id": ObjectId(_id)})

    if data.get('enabled') == True:
        SCRIPT_URL = os.environ.get('API_URL')+f'/api/connections/{_id}/{request.cookies.get("session_token")}/client.sh'
        SCRIPT_NAME = f'client.sh'

        return {
            "data": f"curl -ks {SCRIPT_URL} > {SCRIPT_NAME} && chmod +x {SCRIPT_NAME}"
        }
    else:
        raise HTTPException(status_code=400, detail="Connection is disabled")


@router.get("/{_id}/{token}/client.sh")
async def connection_command(_id: str, token:str, request: Request, response: Response):
    default_response = Response(content="echo 403 Not Authenticated", media_type="text/plain")

    # Check if user is logged in
    session_token = request.cookies.get("session_token") or token
    if not session_token:
        return default_response
    else:
        user_id = redis.get(session_token)
        if not user_id:
            return default_response

    user = await db.users.find_one({"_id": ObjectId(user_id.decode("utf-8"))})
    if not user:
        return default_response

    data = await db.connections.find_one({"_id": ObjectId(_id)})

    if data.get('enabled') == True:
        with open("/ssh/client.sh", "r") as f:
            content = f.read()
            content = content.replace("$SSH_USERNAME", "porthub")
            content = content.replace("$SSH_HOST", os.environ.get("SSH_HOST"))
            content = content.replace("$SSH_PORT", os.environ.get("SSH_PORT"))
            content = content.replace("$INTERNAL_PORT", str(data.get('internal_port')))
            content = content.replace("$EXTERNAL_PORT", str(data.get('external_port')))

            with open("/ssh/key.pem", "r") as key:
                content = content.replace("$SSH_KEY", key.read())
            return Response(content=content, media_type="text/plain")
    else:
        raise HTTPException(status_code=400, detail="Connection is disabled")