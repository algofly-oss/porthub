import os
import motor.motor_asyncio
from .env import *


def get_db():
    # Initialize MongoDB
    mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DATABASE_URI)
    db = mongo_client[MONGO_DATABASE_NAME]
    return db


db = get_db()
