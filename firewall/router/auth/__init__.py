from fastapi import Header, HTTPException

from shared.env import API_KEY


def require_key(x_api_key: str = Header(...)) -> None:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
